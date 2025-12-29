#define FUSE_USE_VERSION 30
#include <fuse.h>
#include "efile_mapping.h"

#include <iostream>
#include <functional>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <libgen.h>

#include "util/util.h"

#define DEBUG_OUTPUT(s...) do {       \
  if (debug_) {                       \
    std::cout << s << std::endl;      \
  }                                   \
} while (0)


#define MYFS_DEBUG_OUTPUT(s...) do {  \
  if (ef->debug_) {                   \
    std::cout << s << std::endl;      \
  }                                   \
} while (0)


namespace miku {

EfileFuseMapping::Node *EfileFuseMapping::Node::AddNode(
    const std::string &name,
    const std::string &raw_file) {
  if (subs.find(name) != subs.end()) {
    return nullptr;
  }

  struct stat stat;
  int32_t ret = lstat(raw_file.c_str(), &stat);
  if (ret != 0) {
    DEBUG_OUTPUT("AddNode lstat <" << raw_file << "> failed.");
    return nullptr;
  }

  std::string new_src_path = get_src_path(src_path, name);
  if (S_ISDIR(stat.st_mode)) {
    auto [d, succ] = subs.insert(
        {name, {name,
                raw_file,
                new_src_path,
                Node::NODE_TYPE_DIR,
                this,
                0,
                {},
                debug_}});
    return succ ? &d->second : nullptr;
  }

  if (!S_ISREG(stat.st_mode)) {
    DEBUG_OUTPUT("lstat <" << raw_file << "> not supported.");
    return nullptr;
  }

  auto [d, succ] = subs.insert(
      {name, {name,
              raw_file,
              new_src_path,
              Node::NODE_TYPE_FILE,
              this,
              0,
              {},
              debug_}});

  return succ ? &d->second : nullptr;
}

EfileFuseMapping::Node *EfileFuseMapping::Node::AddNode(
    const Node &n) {
  if (subs.find(n.name) != subs.end()) {
    return nullptr;
  }

  auto [d, succ] = subs.insert({n.name, n});
  return succ ? &d->second : nullptr;
}

std::string
EfileFuseMapping::Node::get_src_path(const std::string &dname,
                                     const std::string &bname) {
  if (dname == std::string("/")) {
    return dname + bname;
  } else {
    return dname + "/" + bname;
  }
}

EfileFuseMapping::EfileFuseMapping(const char *src_dir,
                                   const char *des_dir,
                                   const char *key,
                                   bool default_auth,
                                   bool debug)
    : src_dir_(get_full_path(src_dir))
    , des_dir_(get_full_path(des_dir))
    , key_(key)
    , default_auth_(default_auth)
    , fuse_(nullptr)
    , root_{"/", "", "/", Node::NODE_TYPE_DIR, nullptr, 0, {}, debug}
    , pid_(getpid())
    , current_exec_(*miku::get_module_path(pid_))  // 失败了直接core掉就好
    , watch_pid_(0)
    , debug_(debug) {
  if (!check_is_dir(src_dir_.c_str())) {
    DEBUG_OUTPUT(src_dir_ << " is not dir.");
    return;
  }

  if (!check_is_dir(des_dir_.c_str())) {
    DEBUG_OUTPUT(des_dir_ << " is not dir.");
    return;
  }

  ReadDir(src_dir_.c_str(), &root_);
  myfs_oper_ = new struct fuse_operations;
  memset(myfs_oper_, 0, sizeof(struct fuse_operations));

  myfs_oper_->init = myfs_init;
  myfs_oper_->destroy = myfs_destroy;
  myfs_oper_->getattr = myfs_getattr;
  myfs_oper_->readdir = myfs_readdir;
  myfs_oper_->open = myfs_open;
  myfs_oper_->read = myfs_read;
  myfs_oper_->write = myfs_write;
  myfs_oper_->create = myfs_create;
  myfs_oper_->truncate = myfs_truncate;
  myfs_oper_->rename = myfs_rename;
  myfs_oper_->mkdir = myfs_mkdir;
  myfs_oper_->rmdir = myfs_rmdir;
  myfs_oper_->unlink = myfs_unlink;
  myfs_oper_->utimens = myfs_utimens;
  myfs_oper_->chmod = myfs_chmod;
}


EfileFuseMapping::~EfileFuseMapping() {
  delete myfs_oper_;
  if (watch_pid_ != 0) {
    thread_watch_pid_.join();
  }
  Stop();
}

int32_t EfileFuseMapping::Start(
    const std::vector<std::string> &cmd,
    const EfileFuseMapping::EventCallback &event_callback,
    void *private_data) const {
  private_data_ = private_data;
  event_callback_ = event_callback;
  char self_exe[BUFFER_SIZE] = {0};
  readlink("/proc/self/exe", self_exe, sizeof(self_exe));
  std::vector<std::string> c = {self_exe,
                                "-o", "allow_other",
                                "-o", "auto_unmount"};
  c.insert(c.end(), cmd.begin(), cmd.end());

  auto n_arg = c.size();
  std::shared_ptr<char *[]> p_arg(new char *[n_arg]);

  for (uint32_t i = 0; i < n_arg; i++) {
    p_arg[i] = const_cast<char *>(c[i].c_str());
  }

  struct fuse_args args = FUSE_ARGS_INIT(static_cast<int32_t>(n_arg),
                                         p_arg.get());
  auto *pfuse = fuse_new(
      &args,
      myfs_oper_,
      sizeof(*myfs_oper_),
      reinterpret_cast<void *>(const_cast<EfileFuseMapping *>(this)));
  if (pfuse == nullptr) {
    DEBUG_OUTPUT("fuse_new failed.");
    return -1;
  }

  if (fuse_mount(pfuse, des_dir_.c_str()) != 0) {
    DEBUG_OUTPUT("fuse_mount failed.");
    fuse_destroy(pfuse);
    return -1;
  }

  fuse_ = reinterpret_cast<void *>(pfuse);
  int32_t ret = fuse_loop(pfuse);
  DEBUG_OUTPUT("ret = " + std::to_string(ret));

  return 0;
}

void EfileFuseMapping::Stop() const {
  if (fuse_ == nullptr) {
    return;
  }
  auto pfuse = reinterpret_cast<struct fuse *>(fuse_);
  fuse_unmount(pfuse);
  fuse_destroy(pfuse);
  fuse_ = nullptr;
  return;
}

bool EfileFuseMapping::AddAuthInfo(const std::string &path,
                                   const std::string &auth_cmd,
                                   bool inh) {
  std::string key_path = path;
  if (key_path.length() == 0) {
    return false;
  }

  if (key_path[0] != '/') {  // 必需从'/'开始
    return false;
  }

  auto path_len = key_path.length();
  if (key_path[path_len - 1] == '/' && path_len > 1) {
    key_path.erase(path_len - 1);
  }

  auto auth = ProcessAuth::from_auth_cmd(auth_cmd.c_str(),
                                         default_auth_,
                                         true,
                                         inh,
                                         debug_);
  if (!auth) {
    return false;
  }

  auto l = auth_lock_.WrLock();
  // 找到auth指针
  auto it = auth_info_.find(*auth);
  if (it == auth_info_.end()) {
    auto ret = auth_info_.insert(*auth);
    if (!ret.second) {
      return false;
    }

    it = ret.first;
  }

  auto *pauth = &(*it);
  auto it_path = path_auth_.find(key_path);
  if (it_path == path_auth_.end()) {
    auto ret_insert =  path_auth_.insert({key_path, {pauth}});
    return ret_insert.second;
  }

  auto &auths = it_path->second;
  for (auto itd = auths.begin(); itd != auths.end(); ++itd) {
    if (**itd == *auth) {  // 删除旧的
      auths.erase(itd);
      break;
    }
  }

  auths.emplace_back(pauth);

  return true;
}

void EfileFuseMapping::EmptyAuthInfo(const std::string &path) {
  std::string key_path = path;
  if (key_path.length() == 0) {
    return;
  }

  if (key_path[0] != '/') {  // 必需从'/'开始
    return;
  }

  auto path_len = key_path.length();
  if (key_path[path_len - 1] == '/' && path_len > 1) {
    key_path.erase(path_len - 1);
  }

  auto l = auth_lock_.WrLock();
  // 找到auth指针
  auto it = path_auth_.find(key_path);
  if (it == path_auth_.end()) {
    path_auth_.insert({key_path, {}});
  } else {
    it->second.clear();
  }
}

bool EfileFuseMapping::SetWatchPid(pid_t pid) {
  auto l = op_lock_.WrLock();
  if (watch_pid_ != 0 || pid == 0) {
    return false;
  }

  watch_pid_ = pid;
  std::thread j([&]() -> void {
      std::string exec_path;
      while (true) {
        do {
          auto new_exec_path = miku::get_module_path(watch_pid_);
          if (!new_exec_path) {
            DEBUG_OUTPUT("watch_pid get_module_path failed.");
            this->Stop();
            return;
          }

          if (exec_path == std::string("")) {
            exec_path = *new_exec_path;
            break;
          }

          if (exec_path != *new_exec_path) {
            DEBUG_OUTPUT("watch_pid exec changed.");
            this->Stop();
            return;
          }
        } while (0);

        std::this_thread::sleep_for(std::chrono::milliseconds(300));
      }
  });
  thread_watch_pid_.swap(j);

  return true;
}

void EfileFuseMapping::SetDebug(bool d) const {
  if (d == debug_) {
    return;
  }

  auto l = op_lock_.WrLock();
  debug_ = d;

  std::function<void (const Node *, bool)> set_node_debug =
        [&set_node_debug](const Node *n, bool d) -> void {
    n->debug_ = d;
    for (auto &[p, sn] : n->subs) {
      set_node_debug(&sn, d);
    }
  };

  set_node_debug(&root_, d);

  for (const auto &a :auth_info_) {
    a.SetDebug(d);
  }
}

int32_t EfileFuseMapping::myfs_read(
    const char *path,
    char *buf,
    size_t size,
    off_t offset,
    struct fuse_file_info *unuse__) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_read. <" << path << ">");

  auto l = ef->op_lock_.WrLock();
  return ef->ReadFileData(path, buf, size, offset);
}

int32_t EfileFuseMapping::myfs_write(
    const char *path,
    const char *buf,
    size_t size,
    off_t offset,
    struct fuse_file_info *unuse__) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_write. <" << path << ">");

  auto l = ef->op_lock_.WrLock();
  return ef->WriteFileData(path, buf, size, offset);
}

int32_t EfileFuseMapping::myfs_create(const char *path,
                                      mode_t mod,
                                      struct fuse_file_info *unuse__) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_create. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_create Auth failed.");
    return -ENOENT;
  }

  auto l = ef->op_lock_.WrLock();
  return ef->CreateNodeFromPath(path, Node::NODE_TYPE_FILE) == nullptr
        ? -ENOENT : 0;
}

int32_t EfileFuseMapping::myfs_truncate(const char *path,
                                        off_t offset,
                                        struct fuse_file_info *unuse__) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_truncate. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_truncate Auth failed.");
    return -ENOENT;
  }

  auto l = ef->op_lock_.WrLock();
  return ef->NodeTruce(path, offset) ? 0 : -ENOENT;
}

int32_t EfileFuseMapping::myfs_utimens(const char *path,
                                       const struct timespec tv[2],
                                       struct fuse_file_info *fi) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_utimens. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_utimens Auth failed.");
    return -ENOENT;
  }

  // nothing
  return 0;
}

int32_t EfileFuseMapping::myfs_chmod(const char *path,
                          mode_t mod,
                          struct fuse_file_info *unuse__) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_chmod. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_chmod Auth failed.");
    return -ENOENT;
  }

  // nothing
  return 0;
}

void *EfileFuseMapping::myfs_init(
    struct fuse_conn_info *conn,
    struct fuse_config *cfg) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_init.");
  if (ef->event_callback_.init != nullptr) {
    ef->event_callback_.init(ef->private_data_);
  }
  return ctx->private_data;
}

void EfileFuseMapping::myfs_destroy(void *private_data) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_destroy.");
  if (ef->event_callback_.destroy != nullptr) {
    ef->event_callback_.destroy(ef->private_data_);
  }
}

int32_t EfileFuseMapping::myfs_rename(const char *old_path,
                                      const char *new_path,
                                      uint32_t flags) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_rename. old_path <" << old_path << ">");
  MYFS_DEBUG_OUTPUT("myfs_rename. new_path <" << new_path << ">");

  if (!ef->Auth(old_path, ctx->pid) || !ef->Auth(new_path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_rename Auth failed.");
    return -ENOENT;
  }

  auto l = ef->op_lock_.WrLock();
  return ef->NodeMove(old_path, new_path) ? 0 : -ENOENT;
}

int32_t EfileFuseMapping::myfs_mkdir(const char *path, mode_t) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_mkdir. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_mkdir Auth failed.");
    return -ENOENT;
  }

  auto l = ef->op_lock_.WrLock();
  return ef->CreateNodeFromPath(path, Node::NODE_TYPE_DIR) == nullptr
        ? -ENOENT : 0;
}

int32_t EfileFuseMapping::myfs_unlink(const char *path) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_unlink. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_unlink Auth failed.");
    return -ENOENT;
  }

  auto l = ef->op_lock_.WrLock();
  return ef->DeleteNodeFromPath(path) ? 0 : -ENOENT;
}

int32_t EfileFuseMapping::myfs_rmdir(const char *path) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_rmdir. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_rmdir Auth failed.");
    return -ENOENT;
  }

  auto l = ef->op_lock_.WrLock();
  return ef->DeleteNodeFromPath(path) ? 0 : -ENOENT;
}

int32_t EfileFuseMapping::myfs_open(const char *path,
                                    struct fuse_file_info *fi) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_open. <" << path << ">");

  if (!ef->Auth(path, ctx->pid)) {
    MYFS_DEBUG_OUTPUT("myfs_open Auth failed.");
    return -ENOENT;
  }

  auto l = ef->op_lock_.WrLock();
  return ef->NodeOpen(path, fi->flags) ? 0 : -ENOENT;
}

int32_t EfileFuseMapping::myfs_readdir(
    const char *path,
    void *buf,
    fuse_fill_dir_t filler,
    off_t offset,
    struct fuse_file_info *fi,
    enum fuse_readdir_flags unuse__) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_readdir. <" << path << ">");

  auto l = ef->op_lock_.WrLock();
  Node *node = ef->GetNodeFromPath(path);
  if (node == nullptr || node->node_type != Node::NODE_TYPE_DIR) {
    MYFS_DEBUG_OUTPUT("myfs_readdir. not dir_path <" << path << ">");
    return -ENOENT;
  }


  for (const auto &[k, v] : node->subs) {
    filler(buf, k.c_str(), NULL, 0, FUSE_FILL_DIR_DEFAULTS);
  }

  return 0;
}

int32_t EfileFuseMapping::myfs_getattr(
    const char *path,
    struct stat *stbuf,
    struct fuse_file_info *unuse__) {
  auto *ctx = fuse_get_context();
  auto *ef = reinterpret_cast<EfileFuseMapping *>(ctx->private_data);
  MYFS_DEBUG_OUTPUT("myfs_getattr. <" << path << ">");

  auto l = ef->op_lock_.WrLock();
  auto *n = ef->GetNodeFromPath(path);

  if (n == nullptr) {
    MYFS_DEBUG_OUTPUT("myfs_getattr. unknow path <" << path << ">");
    return -ENOENT;
  }

  if (n->node_type == Node::NODE_TYPE_FILE) {
    auto e = ef->GetNodeEfile(n);
    if (e == nullptr) {
      return -ENOENT;
    }

    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = e->data_size();
  } else if (n->node_type == Node::NODE_TYPE_DIR) {
    stbuf->st_mode = S_IFDIR | 0644;
    stbuf->st_nlink = 1;
  } else {
    MYFS_DEBUG_OUTPUT("myfs_getattr. unknow node_type <"
                      << n->node_type << ">");
    return -ENOENT;
  }

  return 0;
}

bool EfileFuseMapping::check_is_dir(const char *path) {
  if (path == nullptr) {
    return false;
  }

  struct stat stat;
  int32_t ret = lstat(path, &stat);
  if (ret != 0) {
    return false;
  }

  return S_ISDIR(stat.st_mode);
}

bool EfileFuseMapping::check_is_link(const char *path) {
  if (path == nullptr) {
    return false;
  }

  struct stat stat;
  int32_t ret = lstat(path, &stat);
  if (ret != 0) {
    return false;
  }

  return S_ISLNK(stat.st_mode);
}


std::string
EfileFuseMapping::get_full_path(const char *path) {
  if (path[0] == '\0') {
    return std::string(get_current_dir_name());
  }

  if (path[0] == '/') {
    return std::string(path);
  }

  return std::string(get_current_dir_name()) + "/" + path;
}

std::tuple<std::string, std::string>
EfileFuseMapping::analysis_path(const char *path) {
  const char *idx = path, *p = path;
  std::string bname;
  std::string dname;
  while (true) {
    auto [n, s] = miku::split_string(p, '/');
    if (n == 0) {
      break;
    }

    bname = s;
    idx = p;
    p += n;
  }

  if (path[0] == '/' && idx == path) {
    dname = std::string("/");
  } else {
    dname = std::string(path , idx - path);
  }

  return {dname, bname};
}

void EfileFuseMapping::delete_real_path(const char *path) {
  std::function <void (const std::string &)> delete_dir =
        [&delete_dir](const std::string &path) -> void {
    struct dirent *f = nullptr;
    DIR *dir = opendir(path.c_str());
    while ((f = readdir(dir)) != nullptr) {
      if (strcmp(f->d_name, ".") == 0 || strcmp(f->d_name, "..") == 0) {
        continue;
      }

      std::string fname = path + "/" + f->d_name;
      if (f->d_type == DT_DIR) {
        delete_dir(fname);
      } else {
        unlink(fname.c_str());
      }
    }

    rmdir(path.c_str());
  };

  struct stat stat;
  int32_t ret = lstat(path, &stat);
  if (ret != 0) {  // 不存在(没权限)
    return;
  }

  if (S_ISDIR(stat.st_mode)) {
    delete_dir(path);
  } else {
    unlink(path);
  }
}

EfileFuseMapping::Node *EfileFuseMapping::ReadLink(const char *link_fname,
                                                   Node *cur_node) {
  char buf[BUFFER_SIZE] = {0};
  char real_path[BUFFER_SIZE] = {0};

  auto [dname, bname] = analysis_path(link_fname);

  ssize_t ret = readlink(link_fname, buf, sizeof(buf));
  if (ret < 0) {
    DEBUG_OUTPUT("readlink failed. [" << link_fname << "]");
    return nullptr;
  }

  if (buf[0] == '/') {
    strncpy(real_path, buf, sizeof(real_path));
  } else {
    snprintf(real_path, sizeof(real_path), "%s/%s", dname.c_str(), buf);
  }

  struct stat stat;
  ret = lstat(real_path, &stat);
  if (ret != 0) {
    DEBUG_OUTPUT("readlink failed. lstat [" << link_fname << "]");
    return nullptr;
  }

  if (S_ISDIR(stat.st_mode)) {
    auto pnew_node = cur_node->AddNode(bname, real_path);
    if (pnew_node != nullptr) {
      ReadDir(real_path, pnew_node);
    }
    return pnew_node;
  } else if (S_ISLNK(stat.st_mode)) {
    return ReadLink(real_path, cur_node);
  } else if (S_ISREG(stat.st_mode)) {
    return cur_node->AddNode(bname, real_path);
  } else if (S_ISCHR(stat.st_mode)) {
    // nothing
  } else if (S_ISBLK(stat.st_mode)) {
    // nothing
  } else if (S_ISFIFO(stat.st_mode)) {
    // nothing
  } else if (S_ISSOCK(stat.st_mode)) {
    // nothing
  } else {
    // nothing
  }

  return nullptr;
}

EfileFuseMapping::Node *
EfileFuseMapping::GetNodeFromPath(const char *path) const {
  Node *node = const_cast<Node *>(&root_);
  const char *p = path;
  while (true) {
    auto [n, s] = miku::split_string(p, '/');
    if (n == 0) {
      break;
    }

    // 如果是文件，不会有subs
    auto it = node->subs.find(s);
    if (it == node->subs.end()) {
      return nullptr;
    }
    node = &it->second;
    p += n;
  }

  return node;
}

EfileFuseMapping::Node *
EfileFuseMapping::CreateNodeFromPath(const char *path, Node::NODETYPE t) {
  static auto get_parent_node = [](const char *path, Node *node)
      -> std::tuple<bool, Node *, std::string> {
    const char *p = path;
    while (true) {
      auto [n, s] = miku::split_string(p, '/');
      if (n == 0) {
        return {false, nullptr, ""};
      }

      auto it = node->subs.find(s);
      if (it == node->subs.end()) {
        if (node->node_type != Node::NODE_TYPE_DIR || *(p + n) != '\0') {
          return {false, nullptr, ""};
        } else {
          return {true, node, s};
        }
      }

      node = &it->second;
      p += n;
    }
  };

  auto [succ, node, bname] = get_parent_node(path, const_cast<Node *>(&root_));
  if (!succ) {
    return nullptr;
  }

  std::string raw_file = src_dir_ + path;
  DeleteNodeFromPath(raw_file.c_str());

  uint64_t fno = 0;
  if (t == Node::NODE_TYPE_FILE) {
    std::shared_ptr<miku::EFile> e(new miku::EFile(src_dir_ + path,
                                                   key_,
                                                   true));
    if (!e->is_open()) {
      return nullptr;
    }

    auto st = e->stat();
    if (!st) {
      return nullptr;
    }

    fno = st->st_ino;
    id_to_efile_[fno] = e;
  } else if (t == Node::NODE_TYPE_DIR) {
    if (mkdir(raw_file.c_str(), 0755) != 0) {
      return nullptr;
    }
  }

  return node->AddNode({std::string(bname),
                        raw_file,
                        path,
                        t,
                        node,
                        fno,
                        {}});
}

bool EfileFuseMapping::DeleteNodeFromPath(const char *path) {
  Node *node = GetNodeFromPath(path);
  if (node == nullptr || node->parent == nullptr) {
    return false;
  }

  if (node->node_type == Node::NODE_TYPE_FILE) {
    unlink(node->raw_file.c_str());
    id_to_efile_.erase(node->node_id);
    node->parent->subs.erase(node->name);
  } else if (node->node_type == Node::NODE_TYPE_DIR) {
    rmdir(node->raw_file.c_str());
    node->parent->subs.erase(node->name);
  } else {
    DEBUG_OUTPUT("DeleteNodeFromPath unknow node type.");
    return false;
  }

  return true;
}

int32_t EfileFuseMapping::ReadFileData(const char *path,
                                       char *buf,
                                       size_t size,
                                       off_t offset) {
  Node *node = GetNodeFromPath(path);
  if (node == nullptr || node->node_type != Node::NODE_TYPE_FILE) {
    DEBUG_OUTPUT("ReadFileData. not file_path <" << path << ">");
    return -1;
  }

  auto efile = GetNodeEfile(node);
  efile->seek(offset, SEEK_SET);
  return efile->read(buf, size);
}

int32_t EfileFuseMapping::WriteFileData(const char *path,
                                        const char *buf,
                                        size_t size,
                                        off_t offset) {
  Node *node = GetNodeFromPath(path);
  if (node == nullptr || node->node_type != Node::NODE_TYPE_FILE) {
    DEBUG_OUTPUT("WriteFileData. not file_path <" << path << ">");
    return -ENOENT;
  }

  auto efile = GetNodeEfile(node);
  efile->seek(offset, SEEK_SET);
  auto ret = efile->write(buf, size);
  efile->flush();
  return ret;
}

bool EfileFuseMapping::NodeOpen(const char *path, int32_t flags) {
  bool trunc = flags & O_TRUNC;
  bool creat = flags & O_CREAT;
  Node *node = GetNodeFromPath(path);
  if (node == nullptr) {
    if (!creat) {
      DEBUG_OUTPUT("NodeOpen. not exist <" << path << ">");
      return false;
    }

    return CreateNodeFromPath(path, Node::NODE_TYPE_FILE) != nullptr;
  }

  if (node->node_type != Node::NODE_TYPE_FILE) {
    DEBUG_OUTPUT("NodeOpen. not file_path <" << path << ">");
    return false;
  }

  auto e = GetNodeEfile(node);
  if (trunc) {
    e->truncate(0);
  }

  return e->seek(0, SEEK_SET);
}

bool EfileFuseMapping::NodeTruce(const char *path, off_t offset) {
  Node *node = GetNodeFromPath(path);
  if (node == nullptr || node->node_type != Node::NODE_TYPE_FILE) {
    DEBUG_OUTPUT("NodeTruce. not file_path <" << path << ">");
    return false;
  }

  auto e = GetNodeEfile(node);
  if (e == nullptr) {
    return false;
  }

  return e->truncate(offset);
}

bool EfileFuseMapping::NodeMove(const char *path_raw, const char *path_des) {
  if (strcmp(path_raw, "/") == 0) {
    DEBUG_OUTPUT("NodeMove. can not rename '/'");
    return false;
  }

  Node *node_raw = GetNodeFromPath(path_raw);
  if (node_raw == nullptr) {
    DEBUG_OUTPUT("NodeMove. unfind path_raw <" << path_raw << ">");
    return false;
  }

  Node *node_des = GetNodeFromPath(path_des);
  Node *node_parent = nullptr;
  std::string dname_des, bname_des, dname_src, bname_src, bname;

  if (node_des == nullptr) {
    auto [tmp_d, tmp_b] = analysis_path(path_des);
    dname_des = tmp_d;
    bname_des = tmp_b;
    node_parent = GetNodeFromPath(dname_des.c_str());

    if (node_parent == nullptr ||
        node_parent->node_type != Node::NODE_TYPE_DIR) {  // 父结点非法
      DEBUG_OUTPUT("NodeMove. unfind des path <" << dname_des << ">");
      return false;
    }

    bname = bname_des;
  } else {
    if (node_des->node_type == Node::NODE_TYPE_FILE) {
      // 文件不允许覆盖
      DEBUG_OUTPUT("NodeMove. des path <" << dname_des << "> is file.");
      return false;
    }

    auto [tmp_d, tmp_b] = analysis_path(path_raw);
    dname_src = tmp_d;
    bname_src = tmp_b;
    if (node_des->subs.find(bname_src) != node_des->subs.end()) {
      // 不允许覆盖已存在的
      DEBUG_OUTPUT("NodeMove. des path <" << bname_src << "> can not cover.");
      return false;
    }

    bname = bname_src;
    node_parent = node_des;
  }

  std::string new_src_path = Node::get_src_path(node_parent->src_path, bname);
  std::string new_real_src_path = src_dir_ + new_src_path;
  delete_real_path(new_real_src_path.c_str());
  rename((src_dir_ + node_raw->src_path).c_str(), new_real_src_path.c_str());

  Node *node_new = nullptr;
  if (check_is_link(new_real_src_path.c_str())) {
    node_new = ReadLink(new_real_src_path.c_str(), node_parent);
  } else {
    node_new = node_parent->AddNode(bname, new_real_src_path);
  }

  if (node_raw->node_type == Node::NODE_TYPE_DIR) {
    ReadDir(new_real_src_path.c_str(), node_new);
  }

  // 排除了'/'，一定会有parent
  node_raw->parent->subs.erase(node_raw->name);

  return true;
}

bool EfileFuseMapping::Auth(const std::string &path, pid_t pid) const {
  if (pid == pid_) {  // 自身进程不需要限制
    return true;
  }

  auto current_exec = miku::get_module_path(pid);
  if (current_exec && *current_exec == current_exec_) {  // 自身应用程序不限制
    return true;
  }

  auto [auth_path, auths] = GetAuth(path);
  if (auths == nullptr) {
    return default_auth_;
  }

  do {
    for (const auto &a : *auths) {
      if (a->Auth(pid)) {
        return true;
      }
    }

    if (auth_path == std::string("/")) {
      break;
    }

    if (!(*auths->rbegin())->Inh()) {
      break;
    }

    auto a = GetParentAuth(path);
    auth_path = std::get<0>(a);
    auths = std::get<1>(a);
  } while (auths != nullptr);

  return false;
}

std::shared_ptr<miku::EFile>
EfileFuseMapping::GetNodeEfile(Node *n) {
  if (n == nullptr || n->node_type != Node::NODE_TYPE_FILE) {
    return nullptr;
  }

  if (n->node_id != 0) {
    auto it = id_to_efile_.find(n->node_id);
    if (it != id_to_efile_.end()) {
      if (it->second->is_open()) {
        return it->second;
      } else {
        id_to_efile_.erase(it);
      }
    }

    n->node_id = 0;  // 后面重新打开
  }

  struct stat stat;
  int32_t ret = lstat(n->raw_file.c_str(), &stat);
  if (ret != 0) {
    DEBUG_OUTPUT("GetNodeEfile lstat <" << n->raw_file << "> failed.");
    return nullptr;
  }

  if (!S_ISREG(stat.st_mode)) {
    DEBUG_OUTPUT("lstat <" << n->raw_file << "> not supported.");
    return nullptr;
  }

  uint64_t fid = static_cast<uint64_t>(stat.st_ino);
  auto it_efile = id_to_efile_.find(fid);
  if (it_efile != id_to_efile_.end()) {
    if (it_efile->second->is_open()) {
      n->node_id = fid;
      return it_efile->second;
    } else {
      id_to_efile_.erase(it_efile);
    }
  }

  std::shared_ptr<miku::EFile> efile = std::make_shared<miku::EFile>(
      n->raw_file, key_);
  if (efile->is_open()) {
    id_to_efile_[fid] = efile;
    n->node_id = fid;
    return efile;
  }

  return nullptr;
}

std::tuple<std::string, const std::vector<const ProcessAuth *> *>
EfileFuseMapping::GetParentAuth(const std::string &path) const {
  auto len = path.length();
  if (len == 0) {
    return {std::string(""), nullptr};
  }

  std::shared_ptr<char []> p(new char[len + 1]);
  char *ptr = p.get();

  memcpy(ptr, path.c_str(), len);
  ptr[len] = '\0';
  len--;

  while (len > 1) {
    if (ptr[len] == '/') {
      ptr[len] = '\0';
      auto it = path_auth_.find(std::string(ptr));
      if (it != path_auth_.end()) {
        return {std::string(ptr), &it->second};
      }
    }

    len--;
  }

  auto it = path_auth_.find(std::string("/"));
  if (it != path_auth_.end()) {
    return {std::string("/"), &it->second};
  }

  return {std::string(""), nullptr};
}

std::tuple<std::string, const std::vector<const ProcessAuth *> *>
EfileFuseMapping::GetAuth(const std::string &path) const {
  if (path.empty()) {
    return {std::string("/"), nullptr};
  }

  auto l = auth_lock_.RdLock();
  auto it = path_auth_.find(path);
  if (it != path_auth_.end()) {
    return {path, &it->second};
  }

  return GetParentAuth(path);
}

void EfileFuseMapping::ReadDir(const char *dir_path,
                               Node *cur_node) {
  if (!check_is_dir(dir_path) || cur_node->node_type != Node::NODE_TYPE_DIR) {
    DEBUG_OUTPUT(dir_path << " or node_type is not dir.");
    return;
  }

  DIR *dir = opendir(dir_path);

  struct dirent *f = nullptr;
  while ((f = readdir(dir)) != nullptr) {
    if (strcmp(f->d_name, ".") == 0 || strcmp(f->d_name, "..") == 0) {
      continue;
    }
    Node *pnew_node = nullptr;

    std::string fname = std::string(dir_path) + "/" + f->d_name;
    switch (f->d_type) {
     case DT_REG:  // 文件
      cur_node->AddNode(f->d_name, fname);
      break;
     case DT_DIR:  // 目录
      pnew_node = cur_node->AddNode(f->d_name, fname);
      if (pnew_node != nullptr) {
        ReadDir(fname.c_str(), pnew_node);
      }
      break;
     case DT_LNK:  // 软链
      ReadLink(fname.c_str(), cur_node);
      break;
     case DT_BLK:  // block device
      DEBUG_OUTPUT("DT_BLK: " << fname);
      break;
     case DT_CHR :  // character device
      DEBUG_OUTPUT("DT_CHR: " << fname);
      break;
     case DT_FIFO:  // named pipe
      DEBUG_OUTPUT("DT_FIFO: " << fname);
      break;
     case DT_SOCK:  // UNIX domain socket
      DEBUG_OUTPUT("DT_SOCK: " << fname);
      break;
     case DT_UNKNOWN:  // unknow
      DEBUG_OUTPUT("DT_UNKNOWN: " << fname);
      break;
     default:
      DEBUG_OUTPUT("default: " << fname);
      break;
    }
  }

  return;
}

}  // namespace miku
