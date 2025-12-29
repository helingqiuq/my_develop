#pragma once

#include <string>
#include <optional>

#include <stdint.h>
#include <sys/stat.h>

#include "util/lock_helper.h"

namespace miku {

class EFile {
 public:
  EFile(const std::string &filename,
        const std::string &enc_key,
        bool trunc = false);
  ~EFile();
  int64_t tellp();
  bool seek(int64_t off, int where);
  int64_t write(const char *s, uint64_t len);
  int64_t read(char *s, uint64_t len);
  bool eof() const;
  bool flush();
  bool close();
  bool truncate(uint64_t l);
  uint64_t data_size() const;
  std::optional<struct stat> stat() const;
  bool is_open() const;
  int64_t last_errno() const;
  const std::string &last_err_info() const;

  const std::string &filename() const;

  EFile &operator=(const EFile &e) = delete;
  EFile(const EFile &e);
  EFile(EFile &&e);

 private:
  // 文件信息头部
  struct FileHeader {
    uint64_t data_len;
  };

  struct FileHeaderData {
    union {
      FileHeader hdr;
      char placeholder[1024];
    };
  };

  // 加密块文件大小，必需与加密算法对齐，且是2的N次方
  static const int64_t BLOCK_SIZE = 1024;
  static const int64_t BLOCK_SIZE_ALIGN = ~0ul ^ (BLOCK_SIZE - 1);

  int64_t TransferToFileBaseIdx(int64_t idx) const;
  bool LoadBlock(int64_t idx, bool over_file_size = false);
  bool SaveBlock();
  bool SaveHeader();
  void SaveErrInfo(int64_t err_num, const std::string &err_info);

  // 参数
  const std::string filename_;
  const std::string enc_key_;

  // 运行数据
  mutable miku::LockHelper lock_;  // 锁
  FileHeader hdr_;  // 内存中的数据头，最终同步到文件头部
  int64_t last_errno_;
  std::string last_err_info_;
  int fd_;
  int64_t idx_;  // 读写指针的下标
  int64_t buf_idx_;  // buf初始位置的idx
  char buf_[BLOCK_SIZE];  // 1024字节为一个加密单元，缓存
  bool buf_updated_;  // 数据是否更新，用于判断是否需要保存数据
  bool hdr_updated_;  // 数据头是否更新，用于判断是否需要保存数据头
  bool closed_;  // 是否已关闭
};


}  // namespace miku
