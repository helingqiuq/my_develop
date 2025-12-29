#include "encrypt.h"
#include "encrypt_common.h"
#include "io_context.h"


// OPENSSL 版本标识，30000 3.0以后版本
#define OPENSSL_API_COMPAT 30000

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "openssl/hmac.h"
#include "openssl/aes.h"
#include "openssl/md5.h"
#include "openssl/bio.h"
#include "openssl/buffer.h"
#include "openssl/sha.h"
#include "openssl/evp.h"
#include "openssl/des.h"
#include "openssl/provider.h"

//  openssl 3.0函数名发生变化，使用1.1版本时，需要改下名
#if 0
# define EVP_CIPHER_get_block_size EVP_CIPHER_block_size
# define EVP_CIPHER_get_key_length EVP_CIPHER_key_length
# define EVP_CIPHER_get_iv_length EVP_CIPHER_iv_length
#endif
// f2b,b2f,f2f
// TODO  hex b64 自动分配时的长度问题


__attribute__(( constructor )) static void
encode_init_proc_() {
  // 加载 legacy 提供者
  if (OSSL_PROVIDER_load(NULL, "legacy") == NULL) {
    fprintf(stderr, "Failed to load legacy provider\n");
  }
  if (OSSL_PROVIDER_load(NULL, "default") == NULL) {
    fprintf(stderr, "Failed to load legacy provider\n");
  }
}

static int32_t
miku_evp_encrypt_base(const EVP_CIPHER *cipher,
                      MikuIOContext *ioctx,
                      const uint8_t *p, uint32_t plen,
                      const uint8_t *v, uint32_t vlen,
                      const int32_t padding) {
  assert(cipher != NULL && ioctx != NULL);
  int32_t ret = -1;

  uint32_t block_size = EVP_CIPHER_get_block_size(cipher);
  uint32_t key_len = EVP_CIPHER_get_key_length(cipher);
  uint32_t iv_len = EVP_CIPHER_get_iv_length(cipher);

  uint8_t key[EVP_MAX_KEY_LENGTH] = {0};
  uint8_t iv[EVP_MAX_IV_LENGTH] = {0};

  if (p != NULL && plen > 0) {
    memcpy(key, p, plen > key_len ? key_len : plen);
  }
  if (v != NULL && vlen > 0) {
    memcpy(iv, v, vlen > iv_len ? iv_len : vlen);
  }

  uint8_t *inbuf = NULL, *outbuf = NULL;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    goto finish;
  }

  inbuf = (uint8_t *)malloc(block_size);
  outbuf = (uint8_t *)malloc(block_size);
  if (inbuf == NULL || outbuf == NULL) {
    goto finish;
  }

  if (!EVP_EncryptInit(ctx, cipher, key, iv)) {
    goto finish;
  }

  int32_t outlen = 0;
  int32_t outlen_total = 0;
  int32_t nwrite = 0;
  while (1) {
    memset(inbuf, 0, block_size);
    outlen = 0;
    size_t nd = miku_io_context_read(ioctx, inbuf, block_size);
    if (nd == -1) {
      goto finish;
    }

    if (nd < block_size) {
      if (padding == 0) {
        if (nd == 0) {
          break;
        } else {
          nd = block_size;
        }
      } else {
        if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, nd)) {
          goto finish;
        }
        break;
      }
    }

    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, nd)) {
      goto finish;
    }

    if (outlen > 0) {
      nwrite = miku_io_context_write(ioctx, outbuf, outlen);
      if (nwrite < 0) {
        goto finish;
      }

      outlen_total += nwrite;
    }
  }

  if (!EVP_CIPHER_CTX_set_padding(ctx, padding)) {
    goto finish;
  }

  if (!EVP_EncryptFinal(ctx, outbuf, &outlen)) {
    goto finish;
  }

  if (outlen > 0) {
    nwrite = miku_io_context_write(ioctx, outbuf, outlen);
    if (nwrite < 0) {
      goto finish;
    }

    outlen_total += nwrite;
  }

  nwrite = miku_io_context_flush(ioctx);
  if (nwrite < 0) {
    goto finish;
  }

  if (ioctx->t == EIOCONTEXT_TYPE_M2M || ioctx->t == EIOCONTEXT_TYPE_F2M) {
    outlen_total = nwrite;
  } else {
    outlen_total += nwrite;
  }

  ret = outlen_total;
finish:
  free(inbuf);
  free(outbuf);
  if (ctx != NULL) {
    EVP_CIPHER_CTX_free(ctx);
  }

  return ret;
}

static int32_t
miku_evp_decrypt_base(const EVP_CIPHER *cipher,
                      MikuIOContext *ioctx,
                      const uint8_t *p, uint32_t plen,
                      const uint8_t *v, uint32_t vlen,
                      const int32_t padding) {
  assert(cipher != NULL && ioctx != NULL);
  int32_t ret = -1;

  uint32_t block_size = EVP_CIPHER_get_block_size(cipher);
  uint32_t key_len = EVP_CIPHER_get_key_length(cipher);
  uint32_t iv_len = EVP_CIPHER_get_iv_length(cipher);

  uint8_t key[EVP_MAX_KEY_LENGTH] = {0};
  uint8_t iv[EVP_MAX_IV_LENGTH] = {0};

  if (p != NULL && plen > 0) {
    memcpy(key, p, plen > key_len ? key_len : plen);
  }
  if (v != NULL && vlen > 0) {
    memcpy(iv, v, vlen > iv_len ? iv_len : vlen);
  }

  uint8_t *inbuf = NULL, *outbuf = NULL;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (ctx == NULL) {
    goto finish;
  }

  inbuf = (uint8_t *)malloc(block_size);
  outbuf = (uint8_t *)malloc(block_size);
  if (inbuf == NULL || outbuf == NULL) {
    goto finish;
  }

  if (!EVP_DecryptInit(ctx, cipher, key, iv)) {
    goto finish;
  }

  int32_t outlen = 0;
  int32_t outlen_total = 0;
  int32_t nwrite = 0;
  while (1) {
    memset(inbuf, 0, block_size);
    size_t nd = miku_io_context_read(ioctx, inbuf, block_size);
    if (nd == -1) {
      goto finish;
    }

    if (nd < block_size) {
      break;
    }

    if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, nd)) {
      goto finish;
    }

    if (outlen > 0) {
      nwrite = miku_io_context_write(ioctx, outbuf, outlen);
      if (nwrite < 0) {
        goto finish;
      }

      outlen_total += nwrite;
    }
  }

  if (!EVP_CIPHER_CTX_set_padding(ctx, padding)) {
    goto finish;
  }

  if (!EVP_DecryptFinal(ctx, outbuf, &outlen)) {
    goto finish;
  }

  if (outlen > 0) {
    nwrite = miku_io_context_write(ioctx, outbuf, outlen);
    if (nwrite < 0) {
      goto finish;
    }

    outlen_total += nwrite;
  }

  nwrite = miku_io_context_flush(ioctx);
  if (nwrite < 0) {
    goto finish;
  }

  if (ioctx->t == EIOCONTEXT_TYPE_M2M || ioctx->t == EIOCONTEXT_TYPE_F2M) {
    outlen_total = nwrite;
  } else {
    outlen_total += nwrite;
  }

  ret = outlen_total;
finish:
  free(inbuf);
  free(outbuf);
  if (ctx != NULL) {
    EVP_CIPHER_CTX_free(ctx);
  }

  return ret;
}



// D5 具体定义
#define ENCRYPT_D5_M2M_PROC(ef, em, fn, ep, et, edt, iot, pd)     \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        d, dlen, dout, outlen)) {                                 \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, pd);                      \
  miku_io_context_uninit(&ioctx);                                 \
  return ret;                                                     \


#define ENCRYPT_D5_M2M(ef, em, fn, ep, et, edt, iot)              \
int32_t fn(const uint8_t *d, uint32_t dlen,                       \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           uint8_t *dout, uint32_t outlen) {                      \
  ENCRYPT_D5_M2M_PROC(ef, em, fn, ep, et, edt, iot, 1)            \
}                                                                 \
int32_t fn##_np(const uint8_t *d, uint32_t dlen,                  \
                const uint8_t *p, uint32_t plen,                  \
                const uint8_t *v, uint32_t vlen,                  \
                uint8_t *dout, uint32_t outlen) {                 \
  ENCRYPT_D5_M2M_PROC(ef, em, fn, ep, et, edt, iot, 0)            \
}                                                                 \
int32_t fn##_padding(const uint8_t *d, uint32_t dlen,             \
                     const uint8_t *p, uint32_t plen,             \
                     const uint8_t *v, uint32_t vlen,             \
                     uint8_t *dout, uint32_t outlen,              \
                     int32_t padding) {                           \
  ENCRYPT_D5_M2M_PROC(ef, em, fn, ep, et, edt, iot, padding)      \
}

#define ENCRYPT_D5_M2M_RB_PROC(ef, em, fn, ep, et, edt, iot, pd)  \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
  size_t block_size = EVP_CIPHER_get_block_size(cipher);          \
  size_t nblock = (dlen + block_size - 1) / block_size;           \
  size_t need_memory = nblock * block_size;                       \
  switch (edt) {                                                  \
   case EDATA_TYPE_BIN:                                           \
    break;                                                        \
   case EDATA_TYPE_BASE64:                                        \
    need_memory = miku_b64_dp_encode_bl(need_memory);             \
    break;                                                        \
   case EDATA_TYPE_HEX:                                           \
   default:                                                       \
    need_memory = miku_hex_dp_encode_bl(need_memory);             \
  }                                                               \
  void *da = (void *)malloc(need_memory);                         \
  if (da == NULL) {                                               \
    return -1;                                                    \
  }                                                               \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        d, dlen, da, need_memory)) {                              \
    free(da);                                                     \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, pd);                      \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    rb->d = da;                                                   \
    rb->n = ret;                                                  \
  } else {                                                        \
    free(da);                                                     \
  }                                                               \
  return ret;                                                     \

#define ENCRYPT_D5_M2M_RB(ef, em, fn, ep, et, edt, iot)           \
int32_t fn(const uint8_t *d, uint32_t dlen,                       \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           ResultBuffer *rb) {                                    \
  ENCRYPT_D5_M2M_RB_PROC(ef, em, fn, ep, et, edt, iot, 1)         \
}                                                                 \
int32_t fn##_np(const uint8_t *d, uint32_t dlen,                  \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           ResultBuffer *rb) {                                    \
  ENCRYPT_D5_M2M_RB_PROC(ef, em, fn, ep, et, edt, iot, 0)         \
}                                                                 \
int32_t fn##_padding(const uint8_t *d, uint32_t dlen,             \
                     const uint8_t *p, uint32_t plen,             \
                     const uint8_t *v, uint32_t vlen,             \
                     ResultBuffer *rb,                            \
                     int32_t padding) {                           \
  ENCRYPT_D5_M2M_RB_PROC(ef, em, fn, ep, et, edt, iot, padding)   \
}                                                                 \


#define ENCRYPT_D5_M2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, pd) \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
  ResultBuffer *buf = encrypt_help_result_create();               \
  size_t block_size = EVP_CIPHER_get_block_size(cipher);          \
  size_t nblock = (dlen + block_size - 1) / block_size + 1;       \
  size_t need_memory = nblock * block_size;                       \
  switch (edt) {                                                  \
   case EDATA_TYPE_BIN:                                           \
    break;                                                        \
   case EDATA_TYPE_BASE64:                                        \
    need_memory = miku_b64_dp_encode_bl(need_memory);             \
    break;                                                        \
   case EDATA_TYPE_HEX:                                           \
   default:                                                       \
    need_memory = miku_hex_dp_encode_bl(need_memory);             \
  }                                                               \
  buf->d = (void *)malloc(need_memory);                           \
  if (buf->d == NULL) {                                           \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
    return -1;                                                    \
  }                                                               \
  buf->n = need_memory;                                           \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        d, dlen, buf->d, buf->n)) {                               \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, pd);                      \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    buf->n = ret;                                                 \
    *rb = buf;                                                    \
  } else {                                                        \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
  }                                                               \
  return ret;                                                     \


#define ENCRYPT_D5_M2M_ARB(ef, em, fn, ep, et, edt, iot)          \
int32_t fn(const uint8_t *d, uint32_t dlen,                       \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           ResultBuffer **rb) {                                   \
  ENCRYPT_D5_M2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, 1)        \
}                                                                 \
int32_t fn##_np(const uint8_t *d, uint32_t dlen,                  \
                const uint8_t *p, uint32_t plen,                  \
                const uint8_t *v, uint32_t vlen,                  \
                ResultBuffer **rb) {                              \
  ENCRYPT_D5_M2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, 0)        \
}                                                                 \
int32_t fn##_padding(const uint8_t *d, uint32_t dlen,             \
                     const uint8_t *p, uint32_t plen,             \
                     const uint8_t *v, uint32_t vlen,             \
                     ResultBuffer **rb,                           \
                     int32_t padding) {                           \
  ENCRYPT_D5_M2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, padding)  \
}

#define ENCRYPT_D5_F2M_PROC(ef, em, fn, ep, et, edt, iot, pd)     \
  int64_t fsize = miku_encrypt_file_size(fin);                    \
  if (fsize < 0) {                                                \
    return -1;                                                    \
  }                                                               \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        (const uint8_t *)fin, 0, dout, outlen)) {                 \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, pd);                      \
  miku_io_context_uninit(&ioctx);                                 \
  return ret;                                                     \


#define ENCRYPT_D5_F2M(ef, em, fn, ep, et, edt, iot)              \
int32_t fn(const char *fin,                                       \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           uint8_t *dout, uint32_t outlen) {                      \
  ENCRYPT_D5_F2M_PROC(ef, em, fn, ep, et, edt, iot, 1)            \
}                                                                 \
int32_t fn##_np(const char *fin,                                  \
                const uint8_t *p, uint32_t plen,                  \
                const uint8_t *v, uint32_t vlen,                  \
                uint8_t *dout, uint32_t outlen) {                 \
  ENCRYPT_D5_F2M_PROC(ef, em, fn, ep, et, edt, iot, 0)            \
}                                                                 \
int32_t fn##_padding(const char *fin,                             \
                     const uint8_t *p, uint32_t plen,             \
                     const uint8_t *v, uint32_t vlen,             \
                     uint8_t *dout, uint32_t outlen,              \
                     int32_t padding) {                           \
  ENCRYPT_D5_F2M_PROC(ef, em, fn, ep, et, edt, iot, padding)      \
}


#define ENCRYPT_D5_F2M_RB_PROC(ef, em, fn, ep, et, edt, iot, pd)  \
  int64_t fsize = miku_encrypt_file_size(fin);                    \
  if (fsize < 0) {                                                \
    return -1;                                                    \
  }                                                               \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
  size_t block_size = EVP_CIPHER_get_block_size(cipher);          \
  size_t nblock = (fsize + block_size - 1) / block_size;          \
  size_t need_memory = nblock * block_size;                       \
  switch (edt) {                                                  \
   case EDATA_TYPE_BIN:                                           \
    break;                                                        \
   case EDATA_TYPE_BASE64:                                        \
    need_memory = miku_b64_dp_encode_bl(need_memory);             \
    break;                                                        \
   case EDATA_TYPE_HEX:                                           \
   default:                                                       \
    need_memory = miku_hex_dp_encode_bl(need_memory);             \
  }                                                               \
  void *d = (void *)malloc(need_memory);                          \
  if (rb->d == NULL) {                                            \
    return -1;                                                    \
  }                                                               \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        (const uint8_t *)fin, 0, rb->d, need_memory)) {           \
    free(d);                                                      \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, 1);                       \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    rb->n = ret;                                                  \
    rb->d = d;                                                    \
  } else {                                                        \
    free(d);                                                      \
  }                                                               \
  return ret;                                                     \


#define ENCRYPT_D5_F2M_RB(ef, em, fn, ep, et, edt, iot)           \
int32_t fn(const char *fin,                                       \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           ResultBuffer *rb) {                                    \
  ENCRYPT_D5_F2M_RB_PROC(ef, em, fn, ep, et, edt, iot, 1)         \
}                                                                 \
int32_t fn##_np(const char *fin,                                  \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           ResultBuffer *rb) {                                    \
  ENCRYPT_D5_F2M_RB_PROC(ef, em, fn, ep, et, edt, iot, 0)         \
}                                                                 \
int32_t fn##_padding(const char *fin,                             \
                     const uint8_t *p, uint32_t plen,             \
                     const uint8_t *v, uint32_t vlen,             \
                     ResultBuffer *rb ,                           \
                     int32_t padding) {                           \
  ENCRYPT_D5_F2M_RB_PROC(ef, em, fn, ep, et, edt, iot, padding)   \
}

#define ENCRYPT_D5_F2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, pd) \
  int64_t fsize = miku_encrypt_file_size(fin);                    \
  if (fsize < 0) {                                                \
    return -1;                                                    \
  }                                                               \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
  ResultBuffer *buf = encrypt_help_result_create();               \
  size_t block_size = EVP_CIPHER_get_block_size(cipher);          \
  size_t nblock = (fsize + block_size - 1) / block_size;          \
  size_t need_memory = nblock * block_size;                       \
  switch (edt) {                                                  \
   case EDATA_TYPE_BIN:                                           \
    break;                                                        \
   case EDATA_TYPE_BASE64:                                        \
    need_memory = miku_b64_dp_encode_bl(need_memory);             \
    break;                                                        \
   case EDATA_TYPE_HEX:                                           \
   default:                                                       \
    need_memory = miku_hex_dp_encode_bl(need_memory);             \
  }                                                               \
  buf->d = (void *)malloc(need_memory);                           \
  if (buf->d == NULL) {                                           \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
    return -1;                                                    \
  }                                                               \
  buf->n = need_memory;                                           \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        (const uint8_t *)fin, 0, buf->d, buf->n)) {               \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, pd);                      \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    buf->n = ret;                                                 \
    *rb = buf;                                                    \
  } else {                                                        \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
  }                                                               \
  return ret;                                                     \


#define ENCRYPT_D5_F2M_ARB(ef, em, fn, ep, et, edt, iot)          \
int32_t fn(const char *fin,                                       \
           const uint8_t *p, uint32_t plen,                       \
           const uint8_t *v, uint32_t vlen,                       \
           ResultBuffer **rb) {                                   \
  ENCRYPT_D5_F2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, 1)        \
}                                                                 \
int32_t fn##_np(const char *fin,                                  \
                const uint8_t *p, uint32_t plen,                  \
                const uint8_t *v, uint32_t vlen,                  \
                ResultBuffer **rb) {                              \
  ENCRYPT_D5_F2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, 0)        \
}                                                                 \
int32_t fn##_padding(const char *fin,                             \
                     const uint8_t *p, uint32_t plen,             \
                     const uint8_t *v, uint32_t vlen,             \
                     ResultBuffer **rb,                           \
                     int32_t padding) {                           \
  ENCRYPT_D5_F2M_ARB_PROC(ef, em, fn, ep, et, edt, iot, padding)  \
}                                                                 \

// D4 具体定义
#define ENCRYPT_D4_M2M(ef, em, n, ep, et, edt, iot)               \
  ENCRYPT_D5_M2M(ef, em, n, ep, et, edt, iot)                     \
  ENCRYPT_D5_M2M_RB(ef, em, n##_rb, ep, et, edt, iot)             \
  ENCRYPT_D5_M2M_ARB(ef, em, n##_arb, ep, et, edt, iot)

#define ENCRYPT_D4_F2M(ef, em, n, ep, et, edt, iot)               \
  ENCRYPT_D5_F2M(ef, em, n, ep, et, edt, iot)                     \
  ENCRYPT_D5_F2M_RB(ef, em, n##_rb, ep, et, edt, iot)             \
  ENCRYPT_D5_F2M_ARB(ef, em, n##_arb, ep, et, edt, iot)


#define ENCRYPT_D4_M2F_PROC(ef, em, n, ep, et, edt, iot, pd)      \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        (const uint8_t *)d, dlen, (uint8_t *)fout, pd)) {         \
    return -1;                                                    \
  }                                                               \
                                                                  \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, pd);                      \
  return ret;                                                     \

#define ENCRYPT_D4_M2F(ef, em, n, ep, et, edt, iot)               \
int32_t n(const uint8_t *d, uint32_t dlen,                        \
          const uint8_t *p, uint32_t plen,                        \
          const uint8_t *v, uint32_t vlen,                        \
          const char *fout) {                                     \
  ENCRYPT_D4_M2F_PROC(ef, em, n, ep, et, edt, iot, 0)             \
}                                                                 \
int32_t n##_np(const uint8_t *d, uint32_t dlen,                   \
               const uint8_t *p, uint32_t plen,                   \
               const uint8_t *v, uint32_t vlen,                   \
               const char *fout) {                                \
  ENCRYPT_D4_M2F_PROC(ef, em, n, ep, et, edt, iot, 1)             \
}                                                                 \
int32_t n##_padding(const uint8_t *d, uint32_t dlen,              \
                    const uint8_t *p, uint32_t plen,              \
                    const uint8_t *v, uint32_t vlen,              \
                    const char *fout,                             \
                    int32_t padding) {                            \
  ENCRYPT_D4_M2F_PROC(ef, em, n, ep, et, edt, iot, padding)       \
}

#define ENCRYPT_D4_F2F_PROC(ef, em, n, ep, et, edt, iot, pd)      \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, iot, et, edt,                                     \
        (const uint8_t *)fin, 0, (uint8_t *)fout, 0)) {           \
    return -1;                                                    \
  }                                                               \
                                                                  \
  const EVP_CIPHER *cipher = EVP_##ef##_##em();                   \
  int32_t ret = miku_evp_##ep##_base(                             \
      cipher, &ioctx, p, plen, v, vlen, pd);                      \
  return ret;                                                     \

#define ENCRYPT_D4_F2F(ef, em, n, ep, et, edt, iot)               \
int32_t n(const char *fin,                                        \
          const uint8_t *p, uint32_t plen,                        \
          const uint8_t *v, uint32_t vlen,                        \
          const char *fout) {                                     \
  ENCRYPT_D4_F2F_PROC(ef, em, n, ep, et, edt, iot, 1)             \
}                                                                 \
int32_t n##_np(const char *fin,                                   \
               const uint8_t *p, uint32_t plen,                   \
               const uint8_t *v, uint32_t vlen,                   \
               const char *fout) {                                \
  ENCRYPT_D4_F2F_PROC(ef, em, n, ep, et, edt, iot, 0)             \
}                                                                 \
int32_t n##_padding(const char *fin,                              \
                    const uint8_t *p, uint32_t plen,              \
                    const uint8_t *v, uint32_t vlen,              \
                    const char *fout,                             \
                    int32_t padding) {                            \
  ENCRYPT_D4_F2F_PROC(ef, em, n, ep, et, edt, iot, padding)       \
}


// D3 输入，输出方式
#define ENCRYPT_D3_BIN(ef, em, n, ep, et, edt)                      \
  ENCRYPT_D4_M2M(ef, em, n, ep, et, edt, EIOCONTEXT_TYPE_M2M)       \
  ENCRYPT_D4_F2M(ef, em, n##_f2m, ep, et, edt, EIOCONTEXT_TYPE_F2M) \
  ENCRYPT_D4_M2F(ef, em, n##_m2f, ep, et, edt, EIOCONTEXT_TYPE_M2F) \
  ENCRYPT_D4_F2F(ef, em, n##_f2f, ep, et, edt, EIOCONTEXT_TYPE_F2F)

#define ENCRYPT_D3_HEX ENCRYPT_D3_BIN
#define ENCRYPT_D3_B64 ENCRYPT_D3_BIN


// D2 输入，输出格式
#define ENCRYPT_D2(ef, em, n, ep, et)                               \
  ENCRYPT_D3_BIN(ef, em, miku_##n, ep, et, EDATA_TYPE_BIN)          \
  ENCRYPT_D3_HEX(ef, em, miku_hex_##n, ep, et, EDATA_TYPE_HEX)      \
  ENCRYPT_D3_B64(ef, em, miku_b64_##n, ep, et, EDATA_TYPE_BASE64)   \

// D1, 通用，加密和解密
#define ENCRYPT_D1(ef, em, n)                              \
  ENCRYPT_D2(ef, em, n##_encrypt, encrypt, ETYPE_ENCRYPT)  \
  ENCRYPT_D2(ef, em, n##_decrypt, decrypt, ETYPE_DECRYPT)  \


// D0, 通用，加解密模式
#define ENCRYPT_D0(S, s)                \
  ENCRYPT_D1(s, cbc, s##_cbc)           \
  ENCRYPT_D1(s, ecb, s##_ecb)           \


MIKU_ENCRYPT_MAP(ENCRYPT_D0)


#undef ENCRYPT_D5_M2M
#undef ENCRYPT_D5_M2M_PROC
#undef ENCRYPT_D5_M2M_RB
#undef ENCRYPT_D5_M2M_RB_PROC
#undef ENCRYPT_D5_M2M_ARB
#undef ENCRYPT_D5_M2M_ARB_PROC
#undef ENCRYPT_D5_F2M
#undef ENCRYPT_D5_F2M_PROC
#undef ENCRYPT_D5_F2M_RB
#undef ENCRYPT_D5_F2M_RB_PROC
#undef ENCRYPT_D5_F2M_ARB
#undef ENCRYPT_D5_F2M_ARB_PROC
#undef ENCRYPT_D4_M2M
#undef ENCRYPT_D4_F2M
#undef ENCRYPT_D4_M2F
#undef ENCRYPT_D4_M2F_PROC
#undef ENCRYPT_D4_F2F
#undef ENCRYPT_D4_F2F_PROC
#undef ENCRYPT_D3_BIN
#undef ENCRYPT_D3_B64
#undef ENCRYPT_D3_HEX
#undef ENCRYPT_D2
#undef ENCRYPT_D1
#undef ENCRYPT_D0



