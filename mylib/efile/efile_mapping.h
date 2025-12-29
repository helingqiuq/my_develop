#pragma once

#include "efile/efile.h"

#include <string>
#include <tuple>
#include <map>
#include <set>
#include <vector>
#include <memory>
#include <thread>
#include <functional>

#include "util/lock_helper.h"
#include "efile/process_auth.h"

namespace miku {
class EfileFuseMapping final {
 public:
  using EventCallbackType = std::function<void (void *)>;
  struct EventCallback {
    EventCallbackType init;
    EventCallbackType destroy;
  };

  EfileFuseMapping(const char *src_dir,
                   const char *des_dir,
                   const char *key,
                   bool default_auth = true,  // 如没有权限配制的默认权限.
                                              // : true为通过，false为不通过
                   bool debug = false);
  ~EfileFuseMapping();
  int32_t Start(const std::vector<std::string> &cmd = {},
                const EventCallback &event_callback = {nullptr, nullptr},
                void *private_data = nullptr) const;
  void Stop() const;

  bool AddAuthInfo(const std::string &path,
                   const std::string &auth_cmd,
                   bool inh = true);
  void EmptyAuthInfo(const std::string &path);  // 将某个结点的校验信息置空
  bool SetWatchPid(pid_t pid);  // 如果该pid发生变化则进程退出
  void SetDebug(bool d) const;  // 开关debug

 private:
  struct Node {
    const std::string name;
    const std::string raw_file;  // 原始文件
    const std::string src_path;  // 原始目录下对路径
    enum NODETYPE {
      NODE_TYPE_FILE = 0,
      NODE_TYPE_DIR = 1,
      NODE_TYPE_AUTH = 2,  // 仅有权限配制信息，file或dir也会有权限信息
    } node_type;
    Node *parent;
    uint64_t node_id;
    std::map<std::string, Node> subs;
    mutable bool debug_;

    Node *AddNode(const std::string &name, const std::string &raw_file);
    Node *AddNode(const Node &n);
    static std::string get_src_path(const std::string &dname,
                                    const std::string &bname);
  };

  static constexpr uint64_t BUFFER_SIZE = 4096;
  static bool check_is_dir(const char *path);
  static bool check_is_link(const char *path);
  static std::string get_full_path(const char *path);
  static std::tuple<std::string, std::string> analysis_path(const char *path);
  static void delete_real_path(const char *path);  // 用于删真实文件

  const std::string src_dir_;
  const std::string des_dir_;
  const std::string key_;
  const bool default_auth_;
  mutable void *fuse_;

  struct fuse_operations *myfs_oper_ = nullptr;
  miku::LockHelper op_lock_;
  miku::LockHelper auth_lock_;
  Node root_;
  pid_t pid_;
  std::string current_exec_;
  pid_t watch_pid_;
  std::thread thread_watch_pid_;
  mutable bool debug_;
  // 真实文件id与efile的映射
  std::map<uint64_t, std::shared_ptr<miku::EFile>> id_to_efile_;
  // 鉴权结构体，全程不会变化，所以无需shared_ptr来保存，直接用指针即可
  std::map<std::string, std::vector<const ProcessAuth *>> path_auth_;
  std::set<ProcessAuth> auth_info_;

  mutable EventCallback event_callback_;
  mutable void *private_data_;


  void ReadDir(const char *dir_path, Node *cur_node);
  Node *ReadLink(const char *link_fname, Node *cur_node);

  Node *GetNodeFromPath(const char *path) const;
  Node *CreateNodeFromPath(const char *path,
                           Node::NODETYPE t = Node::NODE_TYPE_FILE);
  bool DeleteNodeFromPath(const char *path);
  int32_t ReadFileData(const char *path,
                       char *buf,
                       size_t size,
                       off_t offset);
  int32_t WriteFileData(const char *path,
                        const char *buf,
                        size_t size,
                        off_t offset);
  bool NodeOpen(const char *path, int32_t flags);
  bool NodeTruce(const char *path, off_t offset = 0);
  bool NodeMove(const char *path_raw, const char *path_des);
  bool Auth(const std::string &path, pid_t pid) const;

  std::shared_ptr<miku::EFile> GetNodeEfile(Node *n);

  std::tuple<std::string, const std::vector<const ProcessAuth *> *>
  GetParentAuth(const std::string &path) const;

  std::tuple<std::string, const std::vector<const ProcessAuth *> *>
  GetAuth(const std::string &path) const;

#ifdef FUSE_USE_VERSION
  static void *myfs_init(struct fuse_conn_info *conn,
                         struct fuse_config *cfg);
  static void myfs_destroy(void *private_data);
  static int32_t
  myfs_getattr(const char *path,
               struct stat *stbuf,
               struct fuse_file_info *unuse__);
  static int
  myfs_readdir(const char *path,
               void *buf,
               fuse_fill_dir_t filler,
               off_t offset,
               struct fuse_file_info *fi,
               enum fuse_readdir_flags unuse__);

  static int32_t myfs_open(const char *path, struct fuse_file_info *fi);
  static int32_t myfs_read(const char *path, char *buf, size_t size,
            off_t offset, struct fuse_file_info *unuse__);
  static int32_t myfs_write(const char *path, const char *buf, size_t size,
            off_t offset, struct fuse_file_info *unuse__);
  static int32_t myfs_create(const char *path,
                             mode_t mod,
                             struct fuse_file_info *unuse__);
  static int32_t myfs_truncate(const char *path,
                               off_t offset,
                               struct fuse_file_info *unuse__);
  static int32_t myfs_rename(const char *old_path,
                             const char *new_path,
                             uint32_t flags);
  static int32_t myfs_mkdir(const char *path, mode_t);
  static int32_t myfs_unlink(const char *path);
  static int32_t myfs_rmdir(const char *path);
  static int32_t myfs_utimens(const char *path,
                              const struct timespec tv[2],
                              struct fuse_file_info *fi);
  static int32_t myfs_chmod(const char *path,
                            mode_t mod,
                            struct fuse_file_info *unuse__);
#endif
};

}  // namespace miku
