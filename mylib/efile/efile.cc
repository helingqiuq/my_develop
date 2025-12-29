#include "efile/efile.h"

#include <iostream>
#include <memory>

#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "encrypt_help/encrypt.h"
#include "util/util.h"

namespace miku {
EFile::EFile(const std::string &filename,
             const std::string &enc_key,
             bool trunc)
    : filename_(filename)
    , enc_key_(enc_key)
    , fd_(open(filename_.c_str(),
               O_CREAT | O_RDWR | (trunc ? O_TRUNC : 0),
               0644))
    , idx_(0)
    , buf_idx_(-1)
    , buf_updated_(false)
    , hdr_updated_(false)
    , closed_(fd_ == -1) {
  if (closed_) {
    SaveErrInfo(-1, "init. open failed failed.");
    return;
  }

  lseek(fd_, 0, SEEK_SET);
  FileHeaderData fd;
  auto [success, n_read] = miku::safe_read(fd_,
                                           reinterpret_cast<char *>(&fd),
                                           sizeof(FileHeaderData));
  (void)n_read;
  if (success) {
    hdr_ = fd.hdr;
  } else {
    hdr_.data_len = 0;
  }

  if (hdr_.data_len == 0) {
    buf_idx_ = 0;  // 不需要加载
  } else {
    if (!LoadBlock(idx_)) {
      close();
      SaveErrInfo(-1, "init. LoadBlock failed.");
      return;
    }
  }

  SaveErrInfo(0, "init. success");
}

EFile::~EFile() {
  if (!closed_) {
    close();
  }
}

EFile::EFile(const EFile &e)
    : filename_(e.filename_)
    , enc_key_(e.enc_key_)
    , fd_(dup(e.fd_))
    , idx_(e.idx_)
    , buf_idx_(e.buf_idx_)
    , buf_updated_(e.buf_updated_)
    , hdr_updated_(e.hdr_updated_)
    , closed_(e.closed_) {
  last_errno_ = e.last_errno_;
  last_err_info_ = e.last_err_info_;
  memcpy(buf_, e.buf_, BLOCK_SIZE);
  hdr_ = e.hdr_;
}

EFile::EFile(EFile &&e)
    : filename_(e.filename_)
    , enc_key_(e.enc_key_)
    , fd_(e.fd_)
    , idx_(e.idx_)
    , buf_idx_(e.buf_idx_)
    , buf_updated_(e.buf_updated_)
    , hdr_updated_(e.hdr_updated_)
    , closed_(e.closed_) {
  last_errno_ = e.last_errno_;
  last_err_info_ = std::move(e.last_err_info_);
  memcpy(buf_, e.buf_, BLOCK_SIZE);
  hdr_ = e.hdr_;
  e.fd_ = -1;
  e.close();
}

bool EFile::close() {
  if (closed_) {
    SaveErrInfo(0, "close. success");
    return true;
  }

  bool ret = flush();

  if (fd_ != -1) {
    ::close(fd_);
  }
  fd_ = -1;
  closed_ = true;

  SaveErrInfo(0, "close. success");
  return ret;
}

uint64_t EFile::data_size() const {
  auto lck = lock_.WrLock();
  if (closed_) {
    return 0;
  }
  return hdr_.data_len;
}

bool EFile::truncate(uint64_t l) {
  auto lck = lock_.WrLock();
  if (closed_ || l >= hdr_.data_len) {
    return false;
  }

  auto base = TransferToFileBaseIdx(l);
  ftruncate(fd_, base + BLOCK_SIZE);

  hdr_.data_len = l;
  hdr_updated_ = true;
  if (static_cast<uint64_t>(idx_) > l) {
    idx_ = l;
    LoadBlock(l);
  }

  return true;
}

std::optional<struct stat> EFile::stat() const {
  auto lck = lock_.WrLock();
  if (closed_) {
    return std::nullopt;
  }

  struct stat s;
  int32_t ret = fstat(fd_, &s);
  if (ret != 0) {
    return std::nullopt;
  }

  return s;
}

bool EFile::is_open() const {
  auto l = lock_.RdLock();
  return !closed_;
}

int64_t EFile::tellp() {
  return idx_;
}

bool EFile::seek(int64_t off, int where) {
  auto lck = lock_.WrLock();
  if (closed_) {
    SaveErrInfo(-1, "seek. file is closed");
    return false;
  }

  int64_t new_idx;

  switch (where) {
   case SEEK_SET:
    new_idx = off;
    break;
   case SEEK_END:
    new_idx = hdr_.data_len + off;
    break;
   case SEEK_CUR:
    [[ fallthrough ]];
   default:
    new_idx = idx_ + off;
    break;
  }

  if (new_idx < 0) {
    new_idx = 0;
  }

  if (static_cast<uint64_t>(new_idx) > hdr_.data_len) {
    new_idx = hdr_.data_len;
  }

  // 判断是否同一区
  int64_t new_base_idx = new_idx & BLOCK_SIZE_ALIGN;
  if (new_base_idx != buf_idx_) {  // 不同区
    if (!SaveBlock()) {
      close();
      SaveErrInfo(-1, "seek. SaveBlock failed");
      return false;
    }
    if (!LoadBlock(new_idx)) {
      close();
      SaveErrInfo(-1, "seek. LoadBlock failed");
      return false;
    }
  }

  idx_ = new_idx;
  SaveErrInfo(0, "seek. success");
  return true;
}

int64_t EFile::write(const char *s, uint64_t len) {
  auto lck = lock_.WrLock();
  if (closed_) {
    SaveErrInfo(-1, "write. file is closed");
    return -1;
  }

  const char *psave = s;
  uint64_t need_write = len;

  while (need_write > 0) {
    bool over_file_size = false;
    int64_t offset = idx_ & ~BLOCK_SIZE_ALIGN;
    uint64_t can_write = idx_ == buf_idx_ ?
                         BLOCK_SIZE :
                         BLOCK_SIZE - offset;
    uint64_t n_write = can_write >= need_write ? need_write : can_write;
    memcpy(buf_ + offset, psave, n_write);
    buf_updated_ = true;
    need_write -= n_write;
    idx_ += n_write;
    psave += n_write;
    if (static_cast<uint64_t>(idx_) > hdr_.data_len) {
      over_file_size = true;
      hdr_.data_len = idx_;
      hdr_updated_ = true;
    }

    if (can_write == n_write) {
      if (!SaveBlock()) {
        close();
        SaveErrInfo(-1, "write. SaveBlock failed");
        return -1;
      }
      if (!LoadBlock(idx_, over_file_size)) {
        close();
        SaveErrInfo(-1, "write. LoadBlock failed");
        return -1;
      }
    }
  }

  SaveErrInfo(0, "write. success");
  return len;  // psave - s;
}

int64_t EFile::read(char *s, uint64_t len) {
  auto lck = lock_.WrLock();
  if (closed_) {
    SaveErrInfo(-1, "read. file is closed");
    return -1;
  }

  if (static_cast<uint64_t>(idx_) == hdr_.data_len) {
    SaveErrInfo(0, "read. eof");
    return 0;
  }

  // 判断要读多少数据
  uint64_t need_read = 0;
  if (idx_ + len > hdr_.data_len) {
    need_read = hdr_.data_len - idx_;
  } else {
    need_read = len;
  }

  char *psave = s;
  while (need_read > 0) {
    // 判断是否切换
    uint64_t offset = idx_ & ~BLOCK_SIZE_ALIGN;
    uint64_t can_read = idx_ == buf_idx_ ?
                        BLOCK_SIZE :
                        BLOCK_SIZE - offset;

    uint64_t n_read = can_read >= need_read ? need_read : can_read;
    memcpy(psave, buf_ + offset, n_read);
    idx_ += n_read;
    need_read -= n_read;
    psave += n_read;

    if (can_read == n_read) {
      if (!SaveBlock()) {
        close();
        SaveErrInfo(-1, "read. SaveBlock failed.");
        return -1;
      }

      if (!LoadBlock(idx_)) {
        close();
        SaveErrInfo(-1, "read. LoadBlock failed.");
        return -1;
      }
    }
  }

  SaveErrInfo(0, "read. success");
  return len;
}

bool EFile::eof() const {
  auto l = lock_.RdLock();
  return static_cast<uint64_t>(idx_) == hdr_.data_len;
}

bool EFile::flush() {
  return SaveBlock() && SaveHeader();
}

int64_t EFile::last_errno() const {
  auto l = lock_.RdLock();
  return last_errno_;
}

const std::string &EFile::last_err_info() const {
  auto l = lock_.RdLock();
  return last_err_info_;
}

const std::string &EFile::filename() const {
  return filename_;
}

bool EFile::SaveHeader() {
  if (!hdr_updated_) {
    SaveErrInfo(0, "SaveHeader. success");
    return true;
  }

  FileHeaderData fd;
  fd.hdr = hdr_;

  lseek(fd_, 0, SEEK_SET);
  auto [success, n_write] = miku::safe_write(
      fd_,
      reinterpret_cast<const char *>(&fd),
      sizeof(FileHeaderData));
  (void)n_write;
  if (!success) {
    SaveErrInfo(-1, "SaveHeader. write header_data failed.");
    return false;
  }

  hdr_updated_ = false;
  SaveErrInfo(0, "SaveHeader. success");
  return true;
}

bool EFile::SaveBlock() {
  //assert(idx <= idx_);
  if (closed_) {
    SaveErrInfo(-1, "SaveBlock. file is closed");
    return false;
  }

  if (!buf_updated_ || hdr_.data_len == 0) {
    SaveErrInfo(0, "SaveBlock. success");
    return true;
  }

  char ebuf[BLOCK_SIZE] = {};
  int32_t ret = miku_aes_256_cbc_encrypt_np(
      reinterpret_cast<const unsigned char *>(buf_),
      BLOCK_SIZE,
      reinterpret_cast<const unsigned char *>(enc_key_.c_str()),
      enc_key_.length(),
      nullptr,
      0,
      reinterpret_cast<unsigned char *>(ebuf),
      BLOCK_SIZE);
  if (ret != BLOCK_SIZE) {
    close();
    SaveErrInfo(-1, "SaveBlock. encrypt failed.");
    return false;
  }

  lseek(fd_, TransferToFileBaseIdx(buf_idx_), SEEK_SET);
  auto [success, n_write] = miku::safe_write(fd_, ebuf, BLOCK_SIZE);
  (void)n_write;
  if (!success) {
    close();
    SaveErrInfo(-1, "SaveBlock write block failed.");
    return false;
  }

  buf_updated_ = false;
  SaveErrInfo(0, "SaveBlock. success");
  return true;
}

// 是否突破上限
bool EFile::LoadBlock(int64_t idx, bool over_file_size) {
  //assert(idx <= idx_);
  if (closed_) {
    SaveErrInfo(-1, "LoadBlock. file is closed");
    return false;
  }

  int64_t need_idx = idx & BLOCK_SIZE_ALIGN;
  if (!buf_updated_ &&  //  可能有强制更新刷新的用法
        need_idx == buf_idx_) {  // 无需更新
    SaveErrInfo(0, "LoadBlock. success");
    return true;
  }


  if (over_file_size) {
    buf_idx_ = need_idx;
    SaveErrInfo(0, "LoadBlock. success");
    return true;
  }

  char ebuf[BLOCK_SIZE] = {};
  lseek(fd_, TransferToFileBaseIdx(idx), SEEK_SET);
  auto [success, ret] = miku::safe_read(fd_, ebuf, BLOCK_SIZE);
  if (!success) {
    SaveErrInfo(-1, "LoadBlock. read failed.");
    return false;
  }

  ret = miku_aes_256_cbc_decrypt_np(
      reinterpret_cast<const unsigned char *>(ebuf),
      BLOCK_SIZE,
      reinterpret_cast<const unsigned char *>(enc_key_.c_str()),
      enc_key_.length(),
      nullptr,
      0,
      reinterpret_cast<unsigned char *>(buf_),
      BLOCK_SIZE);
  if (ret != BLOCK_SIZE) {
    close();
    SaveErrInfo(-1, "LoadBlock. decrypt failed.");
    return false;
  }

  buf_idx_ = need_idx;
  buf_updated_ = false;
  SaveErrInfo(0, "LoadBlock. success");
  return true;
}

int64_t EFile::TransferToFileBaseIdx(int64_t idx) const {
  return (idx & BLOCK_SIZE_ALIGN) + sizeof(FileHeaderData);
}

void EFile::SaveErrInfo(int64_t err_num, const std::string &err_info) {
  last_errno_ = err_num;
  last_err_info_ = err_info;
}
}  // namespace miku
