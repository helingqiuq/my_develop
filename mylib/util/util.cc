#include "util/util.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include <sstream>
#include <functional>
#include <iostream>
#include <fstream>

#include <assert.h>
#include <string.h>

#include "common_define.h"
#include "encrypt_help/encrypt.h"
#include "json/json.h"


namespace miku {

static uint32_t local_ip;
static char local_ip_str[32] = {0};
static std::string s_cur_module_path;
static std::string s_cur_work_path;

pid_t
gettid() {
  return (pid_t)syscall(SYS_gettid);
}

int32_t set_non_blocking_mode(int32_t fd) {
  int32_t options = fcntl(fd, F_GETFL);
  if (options < 0) {
    return -1;
  }

  if ((options & O_NONBLOCK) == O_NONBLOCK) {
    return 0;
  }

  options |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, options) != 0) {
    return -1;
  }

  return 0;
}

int32_t
set_close_on_exec_mode(int32_t fd) {
  int ret;
  ret = fcntl(fd, F_GETFD);
  if (unlikely(ret < 0)) {
    return ret;
  }

  if ((ret & FD_CLOEXEC) == FD_CLOEXEC) {
    return 0;
  }

  ret |= FD_CLOEXEC;
  return fcntl(fd, F_SETFD, ret);
}



int32_t
get_local_ipaddr_raw(const char *peer_addr,
                     struct in_addr *pinaddr) {
  int32_t s;
  int32_t ret;

  // assert(pinaddr != NULL);

  struct sockaddr_in addr_in;
  socklen_t len = sizeof(addr_in);

  if (peer_addr == NULL) {
    return -1;
  }

  s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (s == -1) {
    return -1;
  }

  addr_in.sin_family = AF_INET;
  addr_in.sin_port = htons(6666);
  if (inet_aton(peer_addr, &addr_in.sin_addr) == 0) {
    close(s);
    return -1;
  }

  if (set_non_blocking_mode(s) != 0) {
    close(s);
    return -1;
  }

  do {
    ret = connect(s, reinterpret_cast<struct sockaddr *>(&addr_in), len);
  } while (ret != 0 && errno == EINTR);

  if (ret != 0 && errno != EINPROGRESS) {
    close(s);
    return -1;
  }

  if (getsockname(s,
                  reinterpret_cast<struct sockaddr *>(&addr_in),
                  &len) != 0) {
    close(s);
    return -1;
  }

  close(s);
  *pinaddr = addr_in.sin_addr;

  return 0;
}

static int32_t
get_local_ipaddr_str(const char *peer_addr,
                     char *addr,
                     int32_t addrlen) {
  struct in_addr inaddr;
  if (addr == NULL) {
    return -1;
  }

  if (get_local_ipaddr_raw(peer_addr, &inaddr) != 0) {
    return -1;
  }

  snprintf(addr, addrlen, "%s", inet_ntoa(inaddr));
  return 0;
}

int32_t
get_local_ipaddr_ui(const char *peer_addr,
                    uint32_t *pui) {
  struct in_addr inaddr;
  if (pui == NULL) {
    return -1;
  }

  if (get_local_ipaddr_raw(peer_addr, &inaddr) != 0) {
    return -1;
  }

  *pui = inaddr.s_addr;
  return 0;
}

std::string
gen_id() {
  char buf[128] = {0};
  static uint64_t n = 0;
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);

  snprintf(buf, sizeof(buf), "%lu_%lu_%lu_%lu_%lu_%lu",
      static_cast<uint64_t>(local_ip),
      static_cast<uint64_t>(getpid()),
      static_cast<uint64_t>(gettid()),
      static_cast<uint64_t>(tp.tv_sec),
      static_cast<uint64_t>(tp.tv_nsec),
      __sync_add_and_fetch(&n, 1));

  return std::string(buf);
}

std::vector<std::string>
split(const std::string &s,
      const char &split_char,
      const char &escape_char) {
  std::shared_ptr<char []> pbuf(new char[s.length()]);
  std::vector<std::string> ret;
  const char *pcur = s.c_str();
  uint32_t n = 0;

  if (escape_char == '\0') {
    while (*pcur != '\0') {
      if (*pcur == split_char) {
        ret.emplace_back(pbuf.get(), n);
        n = 0;
        pcur++;
        continue;
      }

      pbuf.get()[n++] = *pcur++;
    }
  } else {
    while (*pcur != '\0') {
      if (*pcur == escape_char) {
        if (*(pcur + 1) == escape_char) {
          pbuf.get()[n++] = escape_char;
          pcur += 2;
          continue;
        }

        if (*(pcur + 1) == split_char) {
          pbuf.get()[n++] = split_char;
          pcur += 2;
          continue;
        }
      }

      if (*pcur == split_char) {
        ret.emplace_back(pbuf.get(), n);
        n = 0;
        pcur++;
        continue;
      }

      pbuf.get()[n++] = *pcur++;
    }
  }

  ret.emplace_back(pbuf.get(), n);

  return ret;
}

std::string
trim(const std::string &s, const char &c) {
  std::string::size_type pos_beg, pos_end;
  pos_beg = s.find_first_not_of(c);
  if (pos_beg == std::string::npos) {
    return std::string("");
  }
  pos_end = s.find_last_not_of(c);
  return s.substr(pos_beg, pos_end - pos_beg + 1);
}

const char *
local_ip4_str() {
  return local_ip_str;
}

void
make_random_string(char *pbuf, uint32_t n) {
  std::random_device dv;
  static const char c[] =
      "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
  for (uint32_t i = 0; i < n; i++) {
    pbuf[i] = c[dv() % (sizeof(c) - 1)];  // 不包含空格
  }
}

std::string
make_random_string(uint32_t n) {
  if (n == 0) {
    return std::string("");
  }

  std::shared_ptr<char []> p(new char[n]);
  char *pbuf = p.get();
  make_random_string(pbuf, n);
  return std::string(pbuf, n);
}

std::tuple<bool, uint32_t>
safe_write(int32_t fd, const char *d, uint64_t n) {
  int64_t ret;
  uint64_t n_write = 0;  // 已经写的数据

  while (n > 0) {
    do {
      ret = ::write(fd, d + n_write, n);
    } while (ret == -1 && errno == EINTR);

    if (ret <= 0) {
      return {false, n_write};
    }

    n_write += ret;
    n -= ret;
  }

  return {true, n_write};
}

std::tuple<bool, uint32_t>
safe_read(int32_t fd, char *d, uint64_t n) {
  int64_t ret;
  uint64_t n_read = 0;  // 已经读的数据

  while (n > 0) {
    do {
      ret = ::read(fd, d + n_read, n);
    } while (ret == -1 && errno == EINTR);

    if (ret <= 0) {
      return {false, n_read};
    }

    n_read += ret;
    n -= ret;
  }

  return {true, n_read};
}

static void
format_pid_info_cmd(char *cmd, uint32_t cmd_l,
                    pid_t pid, const char *sub_path) {
  if (pid == 0) {
    snprintf(cmd, cmd_l, "/proc/self/%s", sub_path);
  } else {
    snprintf(cmd, cmd_l, "/proc/%d/%s", pid, sub_path);
  }
}

static bool
path_escape(const char *path, int index) {
  const char *p;
  int n = 0;
  if (index < 0) {
    return false;
  }

  p = path + index;

  while (p >= path && *p == '\\') {
    n++;
    p--;
  }

  return static_cast<bool>(n % 2);
}

static int
clean_full_path(char *path) {
  int len = strlen(path);
  int i;
  int j;

  if (len == 0) {
    return -1;
  }

  if (path[0] != '/') {
    /* 这里只支持绝对路径 */
    return -1;
  }

  /* 去掉 "//" */
  for (i = len - 1; i >= 0; i--) {
    if (path[i] == '/' && path[i + 1] == '/'
        && !path_escape(path, i - 1)) {
      len -= 1;
      for (j = i; j < len; j++) {
        path[j] = path[j + 1];
      }
      path[len] = '\0';
    }
  }

  /* 去掉 "/." */
  for (i = len - 1; i >= 0; i--) {
    if (i >= 1
        && path[i] == '.'
        && path[i - 1] == '/'
        && (path[i + 1] == '/' || path[i + 1] == '\0')
        && !path_escape(path, i - 2)) {
      /* 找到 "./" */
      i--;
      len -= 2;
      for (j = i; j < len; j++) {
        path[j] = path[j + 2];
      }
      path[len] = '\0';
    }
  }

  /* 去掉 "/.." */
  int n = 0;
  int offset = 0;
  for (i = len - 1; i >= 0; i--) {
    if (i >= 2
        && path[i] == '.'
        && path[i - 1] == '.'
        && path[i - 2] == '/'
        && (path[i + 1] == '\0' || path[i + 1] == '/')
        && !path_escape(path, i - 3)) {
      n++;
      len -= 3;
      i -= 2; /* continue 后i会再自减1 */
      offset += 3;
    } else if (path[i] == '/'
        && !path_escape(path, i - 1)) {
      /* 如果没有处于 "/.."状态，则直接继续即可 */
      if (n == 0) {
        continue;
      }

      /* 如果处于"/.."状态，向前找到 '/', 并计算offset */
      n--;
      offset++;
      len--;
      if (n == 0) {
        for (j = i; j < len; ++j) {
          path[j] = path[j + offset];
        }

        path[len] = '\0';
        offset = 0;
      }
    } else {
      if (n > 0) {
        offset++;
        len--;
      }
    }
  }

  if (n > 0) {
    /* 保留根目录 */
    for (j = 1; j < len; ++j) {
      path[j] = path[j + offset];
    }

    path[len] = '\0';
  }

  if (len == 0) {
    path[0] = '/';
    path[1] = '\0';
  }

  return 0;
}

std::optional<std::string>
get_module_path(pid_t pid) {
  char cmd[64] = {0};
  format_pid_info_cmd(cmd, sizeof(cmd), pid, "exe");

  char buf[4096] = {0};
  ssize_t n = readlink(cmd, buf, sizeof(buf));
  if (n < 0) {
    return std::nullopt;
  }

  return std::string(buf);
}

std::optional<std::string>
get_module_script(pid_t pid) {
  char cmd[64] = {0};
  format_pid_info_cmd(cmd, sizeof(cmd), pid, "cmdline");

  FILE *fp = fopen(cmd, "r");
  if (fp == nullptr) {
    return std::nullopt;
  }

  char buf[4096] = {0};
  fseek(fp, 0, SEEK_SET);
  int64_t total = fread(buf, 1, sizeof(buf), fp);  // 超过4096，是可能失败的
  fclose(fp);
  if (total <= 0) {
    return std::nullopt;
  }

  char *p = buf;
  p += strlen(p) + 1;  // 略过第一个
  while (p - buf < total) {
    if (*p == '-') {
      p += strlen(p) + 1;
      continue;
    }

    if (p[0] == '/') {  // 完整路径
      return std::string(p);
    }

    format_pid_info_cmd(cmd, sizeof(cmd), pid, "cwd");
    char buf_cwd[4096] = {0};  // 超过4096，是可能失败的
    ssize_t n = readlink(cmd, buf_cwd, sizeof(buf_cwd));
    if (n < 0) {
      return std::nullopt;
    }
    strcat(buf_cwd, "/");
    strcat(buf_cwd, p);
    clean_full_path(buf_cwd);

    return std::string(buf_cwd);
  }

  return std::nullopt;
}

std::optional<std::string>
format_full_path(const std::string &raw_path) {
  int32_t len = raw_path.length();
  if (len == 0 || raw_path[0] != '/') {
    return std::nullopt;
  }

  std::shared_ptr<char []> pbuf(new char[len + 1]);
  memcpy(pbuf.get(), raw_path.c_str(), len);
  pbuf.get()[len] = '\0';
  clean_full_path(pbuf.get());

  return std::string(pbuf.get());
}

template <typename T>
std::optional<std::string> get_file_hash(const std::string &fname,
                                         const T &t) {
  // TODO 先用直接取全量数据的方式，后面改成读fd
  FILE *fp = fopen(fname.c_str(), "rb");
  if (fp == NULL) {
    return std::nullopt;
  }

  fseek(fp, 0, SEEK_END);
  uint64_t l = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  std::shared_ptr<char []> buf(new char[l]);
  int64_t ret = fread(buf.get(), 1, l, fp);
  if (ret != static_cast<int64_t>(l)) {
    fclose(fp);
    return std::nullopt;
  }
  fclose(fp);

  return t(reinterpret_cast<const unsigned char *>(buf.get()), l);
  /*
  char md5buffer[33] = {0};
  miku_hex_md5(reinterpret_cast<const unsigned char *>(buf.get()), l,
      nullptr, 0,
      md5buffer, sizeof(md5buffer));

  return std::string(md5buffer);
  */

}

std::optional<std::string>
get_file_md5(const std::string &fname) {
  return get_file_hash(fname,
      [] (const unsigned char *d, uint64_t dlen) -> std::string {
        char buffer[33] = {0};
        miku_hex_md5(d, dlen,
            nullptr, 0,
            buffer, sizeof(buffer));

        return std::string(buffer);
      });
}

std::optional<std::string>
get_file_sha256(const std::string &fname) {
  return get_file_hash(fname,
      [] (const unsigned char *d, uint64_t dlen) -> std::string {
        char buffer[65] = {0};
        miku_hex_sha256(d, dlen,
            nullptr, 0,
            buffer, sizeof(buffer));

        return std::string(buffer);
      });
}

#if 0
std::optional<std::string> get_file_md5(const std::string &fname) {
  // TODO 先用直接取全量数据的方式，后面改成读fd
  FILE *fp = fopen(fname.c_str(), "rb");
  if (fp == NULL) {
    return std::nullopt;
  }

  fseek(fp, 0, SEEK_END);
  uint64_t l = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  std::shared_ptr<char []> buf(new char[l]);
  int64_t ret = fread(buf.get(), 1, l, fp);
  if (ret != static_cast<int64_t>(l)) {
    fclose(fp);
    return std::nullopt;
  }
  fclose(fp);

  char md5buffer[33] = {0};
  miku_hex_md5(reinterpret_cast<const unsigned char *>(buf.get()), l,
      nullptr, 0,
      md5buffer, sizeof(md5buffer));

  return std::string(md5buffer);
}
#endif

std::tuple<uint32_t, std::string>
split_string(const char *s, const char split_word) {
  char buf[1024] = {0};
  const char *p = s;
  uint32_t n = 0;
  uint32_t n_seek = 0;

  while (*p == split_word) {  // 跳过重复的'分隔'
    p++;
    n_seek++;
  }


  if (*p == '\0') {
    return {0, std::string("")};
  }

  char ch = *p++;
  do {
    if (ch == '\\') {
      ch = *p++;
      n_seek++;
      buf[n++] = ch;
    } else {
      buf[n++] = ch;
    }

    ch = *p++;
  } while (ch != split_word && ch != '\0');

  return {n + n_seek, std::string(buf)};
}

#ifndef UNIX_PATH_MAX
# define UNIX_PATH_MAX    (108)
#endif

int32_t
create_unix_lfd(const std::string &a) {
  struct sockaddr_un addr;
  if (a.length() > UNIX_PATH_MAX - 2) {
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  strncpy(addr.sun_path + 1, a.c_str(), UNIX_PATH_MAX - 2);

  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s == -1) {
    return -1;
  }

  set_non_blocking_mode(s);
  if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    close(s);
    return -1;
  }
  if (listen(s, SOMAXCONN) == -1) {
    close(s);
    return -1;
  }

  return s;
}

int32_t
create_tcp_lfd(const std::string &a, uint32_t port) {
  int nfd = socket(AF_INET, SOCK_STREAM, 0);
  if (nfd < 0) {
    return -1;
  }

  const int one = 1;
  setsockopt(nfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(int));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(a.c_str());

  if (bind(nfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(nfd);
    return -1;
  }

  if (listen(nfd, SOMAXCONN) < 0) {
    close(nfd);
    return -1;
  }

  int flags = fcntl(nfd, F_GETFL, 0);//设置socket为非阻塞
  if (0 > flags) {
    close(nfd);
    return -1;
  }

  if (set_non_blocking_mode(nfd) != 0) {
    close(nfd);
    return -1;
  }

  return nfd;
}

bool
is_number(const std::string &s,
          bool allow_neg,
          bool allow_dec) {
  int32_t slen = s.length();
  if (slen == 0) {
    return false;
  }

  bool has_dec = false;
  const char *p = s.c_str();

  if (*p == '-') {
    if (!allow_neg || slen == 1) {
      return false;
    }
    p++;
  }

  char ch;
  while ((ch = *p++) != '\0') {
    if (ch == '.' && allow_dec) {
      if (has_dec) {
        return false;
      }
      has_dec = true;
      continue;
    }

    if (ch > '9' || ch < '0') {
      return false;
    }
  }

  return true;
}

std::string
json_to_string(const Json::Value &jv) {
  Json::StreamWriterBuilder wbuilder;
  wbuilder["indentation"] = "";
  return Json::writeString(wbuilder, jv);
}

std::optional<Json::Value>
json_from_string(const std::string &s) {
  Json::Value jv;
  Json::CharReaderBuilder jreader;
  jreader["collectComments"] = false;
  std::unique_ptr<Json::CharReader> r(jreader.newCharReader());
  std::string errs;
  if (!r->parse(s.c_str(), s.c_str() + s.length(), &jv, &errs) ||
      !jv.isObject()) {
    return std::nullopt;
  }

  return std::move(jv);
}

std::optional<Json::Value>
json_from_file(const std::string &f) {
  Json::Value jv;
  std::ifstream ifile(f, std::ios::binary | std::ios::in);
  if (!ifile.is_open()) {
    return std::nullopt;
  }

  std::string errs;
  Json::CharReaderBuilder jreader;
  jreader["collectComments"] = false;
  bool ret = parseFromStream(jreader, ifile, &jv, &errs);
  ifile.close();
  if (!ret) {
    return std::nullopt;
  }

  return jv;
}

bool
json_sarr_has_value(const Json::Value &ja, const std::string &s) {
  if (!ja.isArray())  {
    return false;
  }

  for (const auto &item : ja) {
    if (item.isString() && item.asString() == s) {
      return true;
    }
  }
  return false;
}

void
json_sarr_remove_value(Json::Value *ja, const std::string &s) {
  if (!ja->isArray()) {
    return;
  }

  for (int32_t i = ja->size() - 1; i >= 0; --i) {
    if ((*ja)[i].isString() && (*ja)[i].asString() == s) {
      ja->removeIndex(i, nullptr);
    }
  }
}


std::tuple<bool, std::string, int32_t>
intstring_div(const std::string &s,
              const int32_t divisor) {
  std::stringstream ss;
  int32_t tmp = 0;
  const char *p = s.c_str();
  std::string quotient;
  int32_t remainder;

  if (divisor == 0) {
    return {false, "", 0};
  }

  while (*p != '\0') {
    if (*p > '9' || *p < '0') {
      return {false, "", 0};
    }
    tmp = tmp * 10 + *p - '0';
    ss << tmp / divisor;
    tmp %= divisor;
    p++;
  }

  remainder = tmp;

  std::string q = ss.str();
  auto index = q.find_first_not_of('0');
  if (index == std::string::npos) {
    if (q[0] == '0') {
      quotient = std::string("0");
    } else {
      quotient = std::move(q);
    }
  } else {
    quotient = std::move(q.substr(index));
  }

  return {true, quotient, remainder};
}

std::tuple<uint32_t, uint64_t>
varint_get(const char *ptr) {
  uint64_t v = 0;
  int offs_cnt = 0;
  do {
    v += ((static_cast<uint32_t>(ptr[offs_cnt] & 0x7f)) << (7 * offs_cnt));
  } while (static_cast<uint8_t>(ptr[offs_cnt++]) & static_cast<uint8_t>(0x80u));
  return {offs_cnt, v};
}

uint32_t
varint_set(uint64_t v, char ptr[10]) {
  uint32_t shift = 0;
  while (true) {
    ptr[shift] = static_cast<char>(0x7fu & v);
    if (v < 0x80u) {
      break;
    } else {
      ptr[shift++] |= static_cast<char>(0x80u);
      v >>= 7;
    }
  }
  return shift + 1;
}

std::string
cfg_get_string(const Json::Value &v,
               const std::string &path,
               const std::string &def) {
  std::function<std::string (const Json::Value &v,
                             std::vector<std::string>::const_iterator,
                             std::vector<std::string>::const_iterator,
                             const std::string &def)> get_proc = [&get_proc] (
                               const Json::Value &v,
                               std::vector<std::string>::const_iterator itb,
                               std::vector<std::string>::const_iterator ite,
                               const std::string &def) -> std::string {
    if (itb == ite) {
      return v.isString() ? v.asString() : def;
    }

    if (v[*itb].isNull()) {
      return def;
    }

    return get_proc(v[*itb], itb + 1, ite, def);
  };

  std::vector<std::string> vpath = miku::split(path, '.');
  if (vpath.size() > 0) {
    return get_proc(v, vpath.begin(), vpath.end(), def);
  } else {
    return def;
  }
}

int64_t
cfg_get_integer(const Json::Value &v,
                const std::string &path,
                int64_t def) {
  std::function<int64_t (const Json::Value &v,
                         std::vector<std::string>::const_iterator,
                         std::vector<std::string>::const_iterator,
                         int64_t def)> get_proc = [&get_proc] (
                           const Json::Value &v,
                           std::vector<std::string>::const_iterator itb,
                           std::vector<std::string>::const_iterator ite,
                           int64_t def) -> int64_t {
    if (itb == ite) {
      if (v.isIntegral()) {
        return v.asInt64();
      } else if (v.isString()) {
        return strtoll(v.asString().c_str(), nullptr, 10);
      } else {
        return def;
      }
    }

    if (v[*itb].isNull()) {
      return def;
    }

    return get_proc(v[*itb], itb + 1, ite, def);
  };

  std::vector<std::string> vpath = miku::split(path, '.');
  if (vpath.size() > 0) {
    return get_proc(v, vpath.begin(), vpath.end(), def);
  } else {
    return def;
  }
}

std::optional<std::string>
get_absolute_path(const char *path_src, int default_type) {
  if (path_src == nullptr) {
    return std::nullopt;
  }

  char buf[4096] = {0};

  /* 如果第一位是'/'，则已经是绝对路径 */
  if (path_src[0] == '/') {
    strncpy(buf, path_src, sizeof(buf) - 1);
  } else {
    switch (default_type) {
     case 1:
      snprintf(buf, sizeof(buf), "%s/%s", s_cur_module_path.c_str(), path_src);
      break;
     case 0:
     default:
      snprintf(buf, sizeof(buf), "%s/%s", s_cur_work_path.c_str(), path_src);
      break;
    }
  }

  if (clean_full_path(buf) != 0) {
    return std::nullopt;
  }

  return std::string(buf);
}

std::string
str_replace(const std::string &raw,
            const std::string &src,
            const std::string &des) {
  std::shared_ptr<char []> p = nullptr;

  uint32_t src_len = src.length();
  uint32_t des_len = des.length();
  if (src_len == 0) {
    return raw;
  }

  if (des_len <= src_len) {
    p = std::shared_ptr<char []>(new char [raw.length() + 1]);
  } else {
    uint32_t times = (des_len + src_len - 1) / src_len;
    p = std::shared_ptr<char []>(new char [raw.length() * times + 1]);
  }

  char *ptr = p.get();
  const char *pcur = raw.c_str();
  const char *pfound = nullptr;

  while ((pfound = strstr(pcur, src.c_str())) != nullptr) {
    uint32_t nbyte = pfound - pcur;
    memcpy(ptr, pcur, nbyte);
    ptr += nbyte;
    memcpy(ptr, des.c_str(), des_len);
    ptr += des_len;
    pcur += nbyte + src_len;
  }

  strcpy(ptr, pcur);

  return std::string(p.get());
}

template int32_t cfg_get<int32_t>(
    const Json::Value &v, const std::string &path, const int32_t &def);
decltype(cfg_get<int32_t>) *cfg_get_i = cfg_get<int32_t>;
template uint32_t cfg_get<uint32_t>(
    const Json::Value &v, const std::string &path, const uint32_t &def);
decltype(cfg_get<uint32_t>) *cfg_get_ui = cfg_get<uint32_t>;
template int64_t cfg_get<int64_t>(
    const Json::Value &v, const std::string &path, const int64_t &def);
decltype(cfg_get<int64_t>) *cfg_get_l = cfg_get<int64_t>;
template uint64_t cfg_get<uint64_t>(
    const Json::Value &v, const std::string &path, const uint64_t &def);
decltype(cfg_get<uint64_t>) *cfg_get_ul = cfg_get<uint64_t>;
template std::string cfg_get<std::string>(
    const Json::Value &v, const std::string &path, const std::string &def);
decltype(cfg_get<std::string>) *cfg_get_s = cfg_get<std::string>;

template int32_t cfg_get_must<int32_t>(
    const Json::Value &v, const std::string &path, const int32_t &def);
decltype(cfg_get_must<int32_t>) *cfg_get_ci = cfg_get_must<int32_t>;
template uint32_t cfg_get_must<uint32_t>(
    const Json::Value &v, const std::string &path, const uint32_t &def);
decltype(cfg_get_must<uint32_t>) *cfg_get_cui = cfg_get_must<uint32_t>;
template int64_t cfg_get_must<int64_t>(
    const Json::Value &v, const std::string &path, const int64_t &def);
decltype(cfg_get_must<int64_t>) *cfg_get_cl = cfg_get_must<int64_t>;
template uint64_t cfg_get_must<uint64_t>(
    const Json::Value &v, const std::string &path, const uint64_t &def);
decltype(cfg_get_must<uint64_t>) *cfg_get_cul = cfg_get_must<uint64_t>;
template std::string cfg_get_must<std::string>(
    const Json::Value &v, const std::string &path, const std::string &def);
decltype(cfg_get_must<std::string>) *cfg_get_cs = cfg_get_must<std::string>;

std::string
ts_to_dtstring(time_t t) {
  char buf[64] = {0};
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
  return std::string(buf);
}

std::string
ts_to_dtstring() {
  char buf[64] = {0};
  time_t t = time(nullptr);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
  return std::string(buf);
}

std::string
ts_to_tstring(time_t t) {
  char buf[32] = {0};
  strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
  return std::string(buf);
}

std::string
ts_to_tstring() {
  char buf[32] = {0};
  time_t t = time(nullptr);
  strftime(buf, sizeof(buf), "%H:%M:%S", localtime(&t));
  return std::string(buf);
}

std::string
ts_to_dstring(time_t t) {
  char buf[32] = {0};
  strftime(buf, sizeof(buf), "%Y-%m-%d", localtime(&t));
  return std::string(buf);
}

std::string
ts_to_dstring() {
  char buf[32] = {0};
  time_t t = time(nullptr);
  strftime(buf, sizeof(buf), "%Y-%m-%d", localtime(&t));
  return std::string(buf);
}

std::string
ts_to_year(time_t t) {
  char buf[16] = {0};
  strftime(buf, sizeof(buf), "%Y", localtime(&t));
  return std::string(buf);
}

std::string
ts_to_year() {
  char buf[16] = {0};
  time_t t = time(nullptr);
  strftime(buf, sizeof(buf), "%Y", localtime(&t));
  return std::string(buf);
}

// unix时间戳转去年 yyyy
std::string
ts_to_last_year(time_t t) {
  char buf[16] = {0};
  struct tm *tm = localtime(&t);
  snprintf(buf, sizeof(buf), "%04d", tm->tm_year + 1900);
  return std::string(buf);
}

std::string
ts_to_last_year() {
  char buf[16] = {0};
  time_t t = time(nullptr);
  struct tm *tm = localtime(&t);
  snprintf(buf, sizeof(buf), "%04d", tm->tm_year + 1900 - 1);
  return std::string(buf);
}

std::optional<time_t>
ts_from_string(const char *st, const char *fmt) {
  struct tm tm_time = {0};
  char *result = strptime(st, fmt, &tm_time);
  if (result == nullptr) {
    return std::nullopt;
  }
  return mktime(&tm_time);
}

std::string
ts_to_string(time_t t, const char *fmt) {
  char buf[64] = {0};
  strftime(buf, sizeof(buf), fmt, localtime(&t));
  return std::string(buf);
}


// 初始化一些数据
static class OnlyInit {
 public:
  OnlyInit() {
    get_local_ipaddr_ui("1.1.1.1", &local_ip);
    get_local_ipaddr_str("1.1.1.1", local_ip_str, sizeof(local_ip_str));
    auto pm = get_module_path();
    if (!pm) {
      std::cerr << "get s_cur_module_path failed." << std::endl;
      exit(1);
    }
    s_cur_module_path = std::move(*pm);

    char cur_work_path[4096] = "";
    getcwd(cur_work_path, sizeof(cur_work_path));
    s_cur_work_path = cur_work_path;
  }
} _init;


}  // namespace miku
