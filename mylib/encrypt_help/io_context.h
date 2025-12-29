#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_MIKU_IO_CONTEXT_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_MIKU_IO_CONTEXT_H_

#include <stdint.h>

#include "openssl/bio.h"

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus

typedef struct MikuIOContext {
  enum {
    EIOCONTEXT_TYPE_M2M = 0,
    EIOCONTEXT_TYPE_M2F,
    EIOCONTEXT_TYPE_F2M,
    EIOCONTEXT_TYPE_F2F,
  } t;

  enum {
    EDATA_TYPE_BIN = 0,
    EDATA_TYPE_HEX,
    EDATA_TYPE_BASE64,
  } edt;

  enum {
    ETYPE_ENCRYPT = 0,
    ETYPE_DECRYPT,
  } et;

  BIO *bio_in;
  BIO *bio_out;
  void *out_buf;
  uint32_t out_buf_len;
} MikuIOContext;

// bool形返回
int32_t miku_io_context_init(MikuIOContext *ioctx,
                             uint32_t t,       // 内存或文件，参考MikuIOContext
                             uint32_t et,      // 加密或解密
                             uint32_t edt,     // 数据割开
                             const uint8_t *din,
                             uint32_t dlen,
                             uint8_t *dout,
                             uint32_t doutlen);
void miku_io_context_uninit(MikuIOContext *ioctx);
// >=0 返回读取的字节数
// -1 失败
int32_t miku_io_context_read(MikuIOContext *ctx,
                             void *buf, uint32_t len);
// >=0 返回写入的字节数
// -1 失败
int32_t miku_io_context_write(MikuIOContext *ctx,
                              const void *buf, uint32_t len);
// >= 0 success
int32_t miku_io_context_flush(MikuIOContext *ctx);

#ifdef __cplusplus
}
#endif  //  __cplusplus

#endif  // ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_MIKU_IO_CONTEXT_H_
