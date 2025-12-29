#pragma once

#include <string>
#include <set>
#include <sstream>

#include <sys/stat.h>
#include <stdint.h>

#include "lock_helper.h"

namespace miku::log {

enum class LogLevel {
  log_level_nolog = 0,
  log_level_error,
  log_level_warn,
  log_level_info,
  log_level_debug,
  log_level_trace,

  log_level_max,
};

class Log {
 public:
  class LogKey {
  public:
      virtual const std::string &String() const = 0;
  };

  Log();
  ~Log();

  void LogBase(const char *file,
               int32_t line,
               const char *function,
               LogLevel level,
               const LogKey *key,
               const char *fmt = nullptr, ...)
               __attribute__(( format(printf, 7, 8)));

  void LogBase(const char *file,
               int32_t line,
               const char *function,
               LogLevel level,
               const LogKey *key,
               const char *fmt,
               va_list ap);

  void LogBase(const char *file,
               int32_t line,
               const char *function,
               LogLevel level,
               const LogKey *key,
               std::stringstream &&ss_log);

  void AttachFd(int32_t fd);
  void DetachFd(int32_t fd);
  LogLevel SetLevel(LogLevel new_log_level);
  LogLevel SetLevel(const char *new_log_level);
  LogLevel Level() const;
  bool SetFilename(const std::string &filename);
  const std::string &FileName() const;
  uint64_t SetMaxFileSize(uint64_t fsize);  // 最小 s_max_log_length
  uint64_t MaxFileSize() const;
  uint32_t SetMaxFileLoop(uint32_t lcnt);  // 最小为1，即写1保存1
  uint32_t MaxFileLoop() const;

  static constexpr uint32_t s_max_log_length = 4096;
 private:
  int32_t OpenFile_(const std::string &fname) const;
  bool MakeDirP_(const std::string &fname) const;
  int64_t UpdateFileSize_(int32_t fd) const;
  bool LoadFileLoopInfo_();  // 读取cur_file_loop_ 当前循环到的位置
  bool MoveNextFile_();  // 写下一个循环文件

  miku::LockHelper lock_;
//  struct stat file_stat_;
  std::string file_name_;
  LogLevel log_level_;
  int32_t fd_file_;
  uint64_t cur_file_size_;
  uint64_t max_file_size_;
  uint32_t max_file_loop_;
  uint32_t cur_file_loop_;
  std::set<int32_t> attach_fds_;
}; //class Log


void log_base(const char *file,
              int32_t line,
              const char *function,
              LogLevel level,
              const log::Log::LogKey *key,
              const char *fmt,
              va_list ap);

void log_base(const char *file,
              int32_t line,
              const char *function,
              LogLevel level,
              const log::Log::LogKey *key,
              const char *fmt = nullptr, ...)
              __attribute__((format(printf, 6, 7)));

void log_base(const char *file,
              uint32_t line,
              const char *function,
              LogLevel level,
              const char *fmt = nullptr, ...)
              __attribute__(( format(printf, 5, 6)));

void log_base(const char *file,
              int32_t line,
              const char *function,
              LogLevel level,
              const log::Log::LogKey *key,
              std::stringstream &&ss);

void log_base(const char *file,
              uint32_t line,
              const char *function,
              LogLevel level,
              std::stringstream &&ss);


LogLevel set_log_level(LogLevel loglevel);
LogLevel set_log_level(const char *level);
void log_attach_fd(int32_t fd);
void log_detach_fd(int32_t fd);
void set_log_filename(const char *filename);
uint32_t set_max_file_loop(uint32_t lcnt);
uint64_t set_file_max_size(uint64_t fsize);

} // namespace miku::log

#define log_key_trace(key, fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_trace, key, fmt)
#define log_key_debug(key, fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_debug, key, fmt)
#define log_key_info(key, fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_info, key, fmt)
#define log_key_warn(key, fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_warn, key, fmt)
#define log_key_error(key, fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_error, key, fmt)



#define log_trace(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_trace, fmt)
#define log_debug(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_debug, fmt)
#define log_info(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_info, fmt)
#define log_warn(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_warn, fmt)
#define log_error(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_error, fmt)

#define LogTrace(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_trace, std::stringstream {} << fmt)
#define LogDebug(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_debug, std::stringstream {} << fmt)
#define LogInfo(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_info, std::stringstream {} << fmt)
#define LogWarn(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_warn, std::stringstream {} << fmt)
#define LogError(fmt...) \
  miku::log::log_base(__FILE__, __LINE__, __FUNCTION__, miku::log::LogLevel::log_level_error, std::stringstream {} << fmt)

