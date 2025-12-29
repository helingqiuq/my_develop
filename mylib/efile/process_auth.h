#pragma once

#include <string>
#include <optional>

#include <stdint.h>

namespace miku {

class ProcessAuth {
 public:
  struct CheckInfo {
    const bool default_value;  // 如果没有设置校验值返回的结果
    const std::string Md5;

    bool operator<(const CheckInfo &c) const;
    bool operator==(const CheckInfo &c) const;
    bool operator!=(const CheckInfo &c) const;
  };

  bool Auth(uint32_t pid) const;  // pid鉴权
  bool Inh() const;  // 获取inh值
  void SetDebug(bool s) const;  // 开关debug

  ProcessAuth(const std::string &exec_path,
              const CheckInfo &exec_check_info = {true},
              const std::string &exec_arg = "",
              const CheckInfo &exec_arg_check_info = {true},
              const uint32_t exec_pid = 0,
              bool inh = true,
              bool debug = false);
  ~ProcessAuth();
  bool operator<(const ProcessAuth &a) const;
  bool operator==(const ProcessAuth &a) const;
  bool operator!=(const ProcessAuth &a) const;

  static std::optional<ProcessAuth>
  from_auth_cmd(const char *cmd,
                bool exec_default = true,
                bool arg_default = true,
                bool inh = true,
                bool debug = false);

 private:
  const std::string ExecPath_;
  const CheckInfo ExecCheckInfo_;
  const std::string ExecArg_;
  const CheckInfo ExecArgCheckInfo_;
  const uint32_t ExecPid_;
  const uint32_t inh_;
  mutable bool debug_;

  bool check(const CheckInfo &c, const std::string &f) const;
  static std::string get_full_path(const char *path);
};

}  // namespace miku
