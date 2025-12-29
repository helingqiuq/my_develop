#include "efile/process_auth.h"

#include <memory>
#include <iostream>

#include "string.h"
#include "unistd.h"

#include "encrypt_help/encrypt.h"
#include "util/util.h"

#define DEBUG_OUTPUT(s...) do {       \
  if (debug_) {                       \
    std::cout << s << std::endl;      \
  }                                   \
} while (0)

namespace miku {

ProcessAuth::ProcessAuth(const std::string &exec_path,
                         const CheckInfo &exec_check_info,
                         const std::string &exec_arg,
                         const CheckInfo &exec_arg_check_info,
                         const uint32_t exec_pid,
                         bool inh,
                         bool debug)
    : ExecPath_(exec_path)
    , ExecCheckInfo_(exec_check_info)
    , ExecArg_(exec_arg)
    , ExecArgCheckInfo_(exec_arg_check_info)
    , ExecPid_(exec_pid)
    , inh_(inh)
    , debug_(debug) {
  // nothing
}

ProcessAuth::~ProcessAuth() {
  // nothing
}

bool
ProcessAuth::CheckInfo::operator<(const ProcessAuth::CheckInfo &c) const {
  if (Md5 != c.Md5) {
    return Md5 < c.Md5;
  }

  return default_value < c.default_value;
}


bool
ProcessAuth::CheckInfo::operator==(const ProcessAuth::CheckInfo &c) const {
  return !(*this < c) && !(c < *this);
}

bool
ProcessAuth::CheckInfo::operator!=(const ProcessAuth::CheckInfo &c) const {
  return !(*this == c);
}

bool ProcessAuth::operator<(const ProcessAuth &a) const {
  if (ExecPath_ != a.ExecPath_) {
    return ExecPath_ < a.ExecPath_;
  }

  if (ExecCheckInfo_ != a.ExecCheckInfo_) {
    return ExecCheckInfo_ < a.ExecCheckInfo_;
  }

  if (ExecArg_ != a.ExecArg_) {
    return ExecArg_ < a.ExecArg_;
  }

  if (ExecArgCheckInfo_ != a.ExecArgCheckInfo_) {
    return ExecArgCheckInfo_ < a.ExecArgCheckInfo_;
  }

  if (ExecPid_ != a.ExecPid_) {
    return ExecPid_ < a.ExecPid_;
  }

  if (inh_ != a.inh_) {
    return inh_ < a.inh_;
  }

  return debug_ < a.debug_;
}

bool
ProcessAuth::operator==(const ProcessAuth &c) const {
  return !(*this < c) && !(c < *this);
}

bool
ProcessAuth::operator!=(const ProcessAuth &c) const {
  return !(*this == c);
}



bool ProcessAuth::Auth(uint32_t pid) const {
  if (ExecPid_ != 0 && ExecPid_ != pid) {
    DEBUG_OUTPUT("pid failed. c:<" << ExecPid_ << ">   d:<" << pid << ">");
    return false;
  }

  auto exec_path = miku::get_module_path(pid);
  if (!exec_path) {
    DEBUG_OUTPUT("get exec_path failed.");
    return false;
  }

  if (*exec_path != ExecPath_) {
    DEBUG_OUTPUT("exec_path failed. c:<" << ExecPath_
                  << ">   d:<" << *exec_path << ">");
    return false;
  }

  if (!check(ExecCheckInfo_, *exec_path)) {
    return false;
  }

  if (ExecArg_.empty()) {
    return true;
  }

  auto script = miku::get_module_script(pid);
  if (!script) {
    DEBUG_OUTPUT("get script failed.");
    return false;
  }

  if (*script != ExecArg_) {
    DEBUG_OUTPUT("script failed. c:<" << ExecArg_
                  << ">   d:<" << *script << ">");
    return false;
  }

  return check(ExecArgCheckInfo_, *script);
}

void ProcessAuth::SetDebug(bool s) const {
  debug_ = s;
}

bool ProcessAuth::Inh() const {
  return inh_;
}


bool ProcessAuth::check(const CheckInfo &c,
                        const std::string &file) const {
  if (c.Md5.empty() /*&& xxx.empty() ...*/) {
    DEBUG_OUTPUT("ret default <" << c.default_value << ">");
    return c.default_value;
  }

  auto ret = miku::get_file_md5(file);
  if (!ret) {
    return false;
  }

  DEBUG_OUTPUT("check md5. c:<" << c.Md5 << "> d:<" << *ret << ">");
  return *ret == c.Md5;
}

std::string
ProcessAuth::get_full_path(const char *path) {
  if (path[0] == '\0') {
    return std::string(get_current_dir_name());
  }

  if (path[0] == '/') {
    return std::string(path);
  }

  auto r = miku::format_full_path(
      std::string(get_current_dir_name()) + "/" + path);
  if (!r) {
    return std::string("");
  }
  return *r;
}

//  如/bin/python#script/root/x.py#md512345678901234567890123456789012
std::optional<ProcessAuth>
ProcessAuth::from_auth_cmd(const char *cmd,
                           bool exec_default,
                           bool arg_default,
                           bool inh,
                           bool debug) {
  const char *pstr = cmd;
  std::string exec_path;
  std::string exec_md5;
  std::string script;
  std::string script_md5;
  uint32_t exec_pid = 0;

  while (true) {
    auto [n, s] = miku::split_string(pstr, '#');
    if (n == 0) {
      break;
    }
    if (exec_path.empty()) {  // 第一个参数必需是exec的路径
      exec_path = get_full_path(s.c_str());
      continue;
    }

    if (strncmp(s.c_str(), "md5", 3) == 0) {
      exec_md5 = std::string(s.c_str() + 3);
    } else if (strncmp(s.c_str(), "pid", 3) == 0) {
      exec_pid = static_cast<uint32_t>(atoi(s.c_str() + 3));
    } else if (strncmp(s.c_str(), "script_md5", 10) == 0) {
      script_md5 = std::string(s.c_str() + 10);
    } else if (strncmp(s.c_str(), "script", 6) == 0) {
      script = get_full_path(s.c_str() + 6);
    }

    pstr += n;
  }

  if (exec_path.empty()) {
    return std::nullopt;
  }

  return ProcessAuth{exec_path, {exec_default, exec_md5},
          script, {arg_default, script_md5}, exec_pid, inh, debug};
}

}  // namespace miku
