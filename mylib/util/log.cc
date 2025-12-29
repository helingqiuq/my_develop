#include "log.h"

#include <sstream>
#include <iostream>
#include <memory>

#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>

#include "common_define.h"
#include "util.h"


namespace miku::log {

static Log s_public_log;  // 默认日志

Log::Log()
  : file_name_("")
  , log_level_(LogLevel::log_level_debug)
  , fd_file_(-1)
  , cur_file_size_(0)
  , max_file_size_(100 * 1024 * 1024)
  , max_file_loop_(10)
  , cur_file_loop_(0) {
}

Log::~Log() {
  if (fd_file_ != -1) {
    close(fd_file_);
  }
}

void
Log::LogBase(const char *file,
             int32_t line,
             const char *function,
             LogLevel level,
             const LogKey *key,
             const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  LogBase(file, line, function, level, key, fmt, ap);
  va_end(ap);
}  // function virtual void LogBase

void
Log::AttachFd(int32_t fd) {
  auto l = lock_.Lock();
  if (unlikely(fd < 0)) {
    return;
  }

  auto it = attach_fds_.find(fd);
  if (unlikely(it != attach_fds_.end())) {
    return ;
  }

  attach_fds_.insert(fd);
}

void
Log::DetachFd(int32_t fd) {
  auto l = lock_.Lock();
  if (fd < 0) {
    return;
  }

  auto it = attach_fds_.find(fd);
  if (likely(it != attach_fds_.end())) {
    attach_fds_.erase(it);
  }
}

const std::string &
Log::FileName() const {
  return file_name_;
}

bool
Log::SetFilename(const std::string &filename) {
  if (filename == file_name_) {
    return true;
  }

  if (filename.length() == 0) {  // 不写文件，视为成功
    auto l = lock_.Lock();
    if (fd_file_ != -1) {
      close(fd_file_);
      fd_file_ = -1;
    }
    return true;
  }

  auto fp = get_absolute_path(filename.c_str());
  if (!fp) {
    return false;
  }

  std::string fname = std::move(*fp);
  int32_t fd = OpenFile_(fname);
  if (fd == -1) {
    return false;
  }

  return lock_.serialization([&]()-> bool {
      int64_t s = UpdateFileSize_(fd);
      if (s < 0) {
        return false;
      }

      if (fd_file_ != -1) {
        close(fd_file_);
      }
      fd_file_ = fd;
      cur_file_size_ = s;
      file_name_ = fname;
      LoadFileLoopInfo_();
      return true;
  });
}

bool
Log::MakeDirP_(const std::string &fname) const {
  if (fname.length() == 0) {
    return false;
  }

  const char *p = fname.c_str();
  const char *s = p;
  int32_t n = 0;
  while (*p != '\0') {
    if (*p == '/') {
      mkdir(std::string(s, n).c_str(), 0755);
    }
    n++;
    p++;
  }

  return true;
}

int32_t
Log::OpenFile_(const std::string &fname) const {
  if (unlikely(fname.length() == 0)) {
    return -1;
  }

  if (unlikely(!MakeDirP_(fname))) {
    return -1;
  }

  int32_t fd = open(fname.c_str(),
      O_CREAT | O_APPEND | O_WRONLY | O_NOFOLLOW | O_NOCTTY,
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
  if (unlikely(fd == -1)) {
    return -1;
  }

  set_close_on_exec_mode(fd);
  //fstat(fd_file_, &file_stat_);

  return fd;
}

int64_t
Log::UpdateFileSize_(int32_t fd) const {
  if (fd == -1) {
    return -1;
  }

  return lseek(fd, 0, SEEK_END);
}

bool
Log::LoadFileLoopInfo_() {  // 执行这个函数必需在锁内
  // 找到 filename + "_1~max_file_loop_"最新的文件的下一个, 如果没有，则取0
  if (file_name_.length() == 0) {  // 未设置文件
    return false;
  }

  uint32_t cur_loop = 0;
  time_t newest = 0;

  for (uint32_t i = 1; i <= max_file_loop_; i++) {
    std::string fname =  file_name_ + "_" + std::to_string(i);
    struct stat sb;
    int32_t ret = lstat(fname.c_str(), &sb);
    if (ret != 0) {
      continue;
    }

    if (sb.st_ctime >= newest) {
      cur_loop = i;
      newest = sb.st_ctime;
    }
  }

  if (cur_loop == 0) {
    cur_file_loop_ = 1;
  } else {
    cur_file_loop_ = cur_loop >= max_file_loop_ ? 1 : cur_loop + 1;
  }
  return true;
}

bool
Log::MoveNextFile_() {  // 执行这个函数必需在锁内
  if (fd_file_ < 0) {
    return false;
  }

  close(fd_file_);
  std::string fname = file_name_ + "_" + std::to_string(cur_file_loop_);
  rename(file_name_.c_str(), fname.c_str());
  cur_file_loop_++;
  if (cur_file_loop_ > max_file_loop_) {
    cur_file_loop_ = 1;
  }

  fd_file_ = OpenFile_(file_name_);
  return true;
}

void
Log::LogBase(const char *file,
             int32_t line,
             const char *function,
             LogLevel level,
             const LogKey *key,
             const char *fmt,
             va_list ap) {
  char buffer[s_max_log_length] = {0};
  vsnprintf(buffer, sizeof(buffer), fmt, ap);
  LogBase(file, line, function, level, key, std::stringstream {} << buffer);
}

void Log::LogBase(const char *file,
                  int32_t line,
                  const char *function,
                  LogLevel level,
                  const LogKey *key,
                  std::stringstream &&ss_log) {
  if (log_level_ < level) {
    return;
  }

  int32_t process_id = getpid();
  int32_t thread_id = gettid();

  struct tm tm;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  localtime_r(&tv.tv_sec, &tm);

  std::stringstream ss, ss_file;
  char buffer[s_max_log_length] = {0}, buffer_file[s_max_log_length] = {0};
  switch (level) {
   case LogLevel::log_level_debug:
    snprintf(buffer, sizeof(buffer), "DEBUG %02d-%02d %02d:%02d:%02d.%06ld %d %d \033[45;32m%s@%d\033[0;32m",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    snprintf(buffer_file, sizeof(buffer_file), "DEBUG %02d-%02d %02d:%02d:%02d.%06ld %d %d %s@%d",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    break;
   case LogLevel::log_level_trace:
    snprintf(buffer, sizeof(buffer), "TRACE %02d-%02d %02d:%02d:%02d.%06ld %d %d \033[45;36m%s@%d\033[0;36m",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    snprintf(buffer_file, sizeof(buffer_file), "TRACE %02d-%02d %02d:%02d:%02d.%06ld %d %d %s@%d",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    break;
   case LogLevel::log_level_info:
    snprintf(buffer, sizeof(buffer), "INFO %02d-%02d %02d:%02d:%02d.%06ld %d %d \033[45;34m%s@%d\033[0;34m",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    snprintf(buffer_file, sizeof(buffer_file), "INFO %02d-%02d %02d:%02d:%02d.%06ld %d %d %s@%d",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    break;
   case LogLevel::log_level_warn:
    snprintf(buffer, sizeof(buffer), "WARN %02d-%02d %02d:%02d:%02d.%06ld %d %d \033[45;33m%s@%d\033[0;33m",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    snprintf(buffer_file, sizeof(buffer_file), "WARN %02d-%02d %02d:%02d:%02d.%06ld %d %d %s@%d",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    break;
   case LogLevel::log_level_error:
    snprintf(buffer, sizeof(buffer), "ERROR %02d-%02d %02d:%02d:%02d.%06ld %d %d \033[45;31m%s@%d\033[0;31m",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    snprintf(buffer_file, sizeof(buffer_file), "ERROR %02d-%02d %02d:%02d:%02d.%06ld %d %d %s@%d",
        tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long>(tv.tv_usec), process_id, thread_id, file, line);
    break;
   default:
    break;
  }

  ss << buffer;
  ss_file << buffer_file;

  std::string raw_log = ss_log.str();
  ss << " [" << function << "]";
  ss_file << " [" << function << "]";
  if (key != nullptr) {
    ss << "<" <<  key->String() << ">: ";
    ss_file << "<" <<  key->String() << ">: ";
  } else {
    ss << ": ";
    ss_file << ": ";
  }
  ss << raw_log << "\n\033[0m";
  ss_file << raw_log << "\n";

  std::string s = ss.str();
  for (auto it = attach_fds_.begin(); it != attach_fds_.end(); ++it) {
    write(*it, s.c_str(), s.length());
  }

  s = ss_file.str();
  if (fd_file_ < 0 && file_name_.length() != 0) {
    fd_file_ = OpenFile_(file_name_);  // 尝试打开文件
  }

  if (fd_file_ >= 0) {
    uint32_t wlen = s.length();
    auto l = lock_.Lock();
    if (cur_file_size_ + wlen > max_file_size_) {
      MoveNextFile_();
    }

    if (fd_file_ >= 0) {
      int32_t nwrite = write(fd_file_, s.c_str(), wlen);
      if (nwrite >= 0) {
        cur_file_size_ += nwrite;
      } else {
        std::cerr << "write log_file failed. " << file_name_ << std::endl;
      }
    }
  }
}



LogLevel
Log::SetLevel(LogLevel new_log_level) {
  if (new_log_level >= LogLevel::log_level_max) {
    return log_level_;
  }

  LogLevel old_log_level = log_level_;
  log_level_ = new_log_level;
  return old_log_level;
}

LogLevel
Log::SetLevel(const char *l) {
  char lkey[6] = "";  // 最长六个字符

  for (int32_t i = 0; i < 5; i++) {
    if (l[i] == '\0') {
      break;
    }

    lkey[i] = ::toupper(l[i]);
  }

  if (strcmp(lkey, "NOLOG") == 0) {
    return s_public_log.SetLevel(LogLevel::log_level_nolog);
  } else if (strcmp(lkey, "ERROR") == 0) {
    return s_public_log.SetLevel(LogLevel::log_level_error);
  } else if (strcmp(lkey, "WARN") == 0) {
    return s_public_log.SetLevel(LogLevel::log_level_warn);
  } else if (strcmp(lkey, "INFO") == 0) {
    return s_public_log.SetLevel(LogLevel::log_level_info);
  } else if (strcmp(lkey, "DEBUG") == 0) {
    return s_public_log.SetLevel(LogLevel::log_level_debug);
  } else if (strcmp(lkey, "TRACE") == 0) {
    return s_public_log.SetLevel(LogLevel::log_level_trace);
  } else if (strcmp(lkey, "MAX") == 0) {
    return s_public_log.SetLevel(LogLevel::log_level_max);
  }

  return Level();
}

LogLevel
Log::Level() const {
  return log_level_;
}

uint64_t
Log::SetMaxFileSize(uint64_t fsize) {
  if (fsize < s_max_log_length) {
    return max_file_size_;
  }

  uint64_t old = max_file_size_;
  max_file_size_ = fsize;
  return old;
}

uint64_t
Log::MaxFileSize() const {
  return max_file_size_;
}

uint32_t
Log::SetMaxFileLoop(uint32_t lcnt) {
  if (lcnt >= 1) {
    uint32_t old = max_file_loop_;
    max_file_loop_ = lcnt;
    return old;
  } else {
    return max_file_loop_;
  }
}

uint32_t
Log::MaxFileLoop() const {
  return max_file_loop_;
}




void
log_base(const char *file,
         int32_t line,
         const char *function,
         LogLevel loglevel,
         const log::Log::LogKey *key,
         const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  s_public_log.LogBase(file, line, function, loglevel, key, fmt, ap);
  va_end(ap);
}

void
log_base(const char *file,
         int32_t line,
         const char *function,
         LogLevel loglevel,
         const log::Log::LogKey *key,
         const char *fmt,
         va_list ap) {
  s_public_log.LogBase(file, line, function, loglevel, key, fmt, ap);
}

LogLevel
set_log_level(LogLevel loglevel) {
  return s_public_log.SetLevel(loglevel);
} // function set_log_level
  //
LogLevel
set_log_level(const char *l) {
  return s_public_log.SetLevel(l);
} // function set_log_level



 void
 log_base(const char *file,
          uint32_t line,
          const char *function,
          LogLevel level,
          const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  s_public_log.LogBase(file, line, function, level, nullptr, fmt, ap);
  va_end(ap);
} // function log_base

void log_base(const char *file,
              int32_t line,
              const char *function,
              LogLevel level,
              const log::Log::LogKey *key,
              std::stringstream &&ss) {
  s_public_log.LogBase(file, line, function, level, key, std::move(ss));
}

void log_base(const char *file,
              uint32_t line,
              const char *function,
              LogLevel level,
              std::stringstream &&ss) {
  s_public_log.LogBase(file, line, function, level, nullptr, std::move(ss));
}


void
log_attach_fd(int32_t fd) {
  s_public_log.AttachFd(fd);
}

void
log_detach_fd(int32_t fd) {
  s_public_log.DetachFd(fd);
}

void
set_log_filename(const char *filename) {
  s_public_log.SetFilename(filename);
}


uint32_t
set_max_file_loop(uint32_t lcnt) {
  return s_public_log.SetMaxFileLoop(lcnt);
}

uint64_t
set_file_max_size(uint64_t fsize) {
  return s_public_log.SetMaxFileSize(fsize);
}

}  // namespace miku::log
