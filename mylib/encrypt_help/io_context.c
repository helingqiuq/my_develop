#include "io_context.h"

#include <string.h>
#include <assert.h>

#include "openssl/pem.h"

#include "encrypt_common.h"

// bool形返回
int32_t
miku_io_context_init(MikuIOContext *ioctx,
                     uint32_t t,       // 内存或文件
                     uint32_t et,      // 加密或解密
                     uint32_t edt,     // 数据割开
                     const uint8_t *din,
                     uint32_t dlen,
                     uint8_t *dout,
                     uint32_t doutlen) {
  ioctx->t = t;
  ioctx->et = et;
  ioctx->edt = edt;
  ioctx->out_buf = dout;
  ioctx->out_buf_len = doutlen;

  switch (t) {
   case EIOCONTEXT_TYPE_M2M:
    ioctx->bio_in = BIO_new_mem_buf(din, dlen);
    ioctx->bio_out = BIO_new(BIO_s_mem());
    break;

   case EIOCONTEXT_TYPE_M2F:
    ioctx->bio_in = BIO_new_mem_buf(din, dlen);
    ioctx->bio_out = BIO_new_file((const char *)dout, "wb");
    break;

   case EIOCONTEXT_TYPE_F2M:
    ioctx->bio_in = BIO_new_file((const char *)din, "rb");
    ioctx->bio_out = BIO_new(BIO_s_mem());
    break;

   case EIOCONTEXT_TYPE_F2F:
    ioctx->bio_in = BIO_new_file((const char *)din, "rb");
    ioctx->bio_out = BIO_new_file((const char *)dout, "wb");
    break;

   default:
    assert(0);
  }

  if (ioctx->bio_in == NULL || ioctx->bio_out == NULL) {
    goto err;
  }

  if (edt == EDATA_TYPE_BASE64) {
    BIO *b64 = BIO_new(BIO_f_base64());
    if (b64 == NULL) {
      goto err;
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    if (et == ETYPE_ENCRYPT) {
      ioctx->bio_out = BIO_push(b64, ioctx->bio_out);
    } else /*if (et == ETYPE_DECRYPT)*/ {
      ioctx->bio_in = BIO_push(b64, ioctx->bio_in);
    }
  }

  return 1;
err:
  if (ioctx->bio_in == NULL) {
    BIO_free(ioctx->bio_in);
    ioctx->bio_in = NULL;
  }

  if (ioctx->bio_out == NULL) {
    BIO_free(ioctx->bio_out);
    ioctx->bio_out = NULL;
  }

  return 0;
}

void
miku_io_context_uninit(MikuIOContext *ioctx) {
  if (ioctx->bio_in != NULL) {
    BIO_free_all(ioctx->bio_in);
    ioctx->bio_in = NULL;
  }

  if (ioctx->bio_out != NULL) {
    (void)BIO_flush(ioctx->bio_out);
    BIO_free_all(ioctx->bio_out);
    ioctx->bio_out = NULL;
  }
}

// >=0 返回读取的字节数
// -1 失败
int32_t
miku_io_context_read(MikuIOContext *ctx, void *buf, uint32_t len) {
  if (len == 0) {
    return 0;
  }

  if (ctx->edt == EDATA_TYPE_HEX && ctx->et == ETYPE_DECRYPT) {
    uint32_t blen = miku_hex_dp_encode_bl(len);
    char *buff = (char *)malloc(blen);
    if (buff == NULL) {
      return -1;
    }
    int32_t ret = BIO_read(ctx->bio_in, buff, blen);
    if (ret > 0) {
      ret = miku_hex_decode(buff, ret, buf, len);
    }
    free(buff);
    return ret;
  } else {
    return BIO_read(ctx->bio_in, buf, len);
  }
}

// >=0 返回写入的字节数
// -1 失败
int32_t
miku_io_context_write(MikuIOContext *ctx, const void *buf, uint32_t len) {
  int32_t ret = 0;
  if (ctx->edt == EDATA_TYPE_HEX && ctx->et == ETYPE_ENCRYPT) {
    uint32_t blen = miku_hex_dp_encode_bl(len);
    char *buff = (char *)malloc(blen);
    if (buff == NULL) {
      return -1;
    }
    ret = miku_hex_encode(buf, len, buff, blen);
    ret = BIO_write(ctx->bio_out, buff, ret);
    free(buff);
  } else {
    ret = BIO_write(ctx->bio_out, buf, len);
  }

  return ret;
}

// >= 0 success
int32_t
miku_io_context_flush(MikuIOContext *ctx) {
  int32_t ret = BIO_flush(ctx->bio_out);
  if (!ret) {
    return -1;
  }

  if (ctx->t == EIOCONTEXT_TYPE_M2M || ctx->t == EIOCONTEXT_TYPE_F2M) {
    BUF_MEM *bptr;
    BIO_get_mem_ptr(ctx->bio_out, &bptr);
    uint32_t len = bptr->length;
    if (len > ctx->out_buf_len) {
      return -1;
    }
    ret = len;
    memcpy(ctx->out_buf, bptr->data, len);
  } else {
    ret = 0;  // 不考虑文件不够存的情况
  }

  return ret;
}
