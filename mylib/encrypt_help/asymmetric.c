#include "asymmetric.h"

#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/err.h"

#include "io_context.h"
#include "encrypt_common.h"

// for debug
__attribute__ (( unused )) static void err_print() {
  uint32_t e = ERR_get_error();
  char msg[1024] = {0};
  ERR_error_string(e, msg);
  printf("errno = %d\n", e);
  printf("errmsg = %s\n", msg);
}


// bool 型函数
typedef int32_t (*miku_set_padding_proc)(EVP_PKEY_CTX *ctx/*, int32_t pt*/);
// 返回padding保留
typedef int32_t (*miku_padding_size_proc)(/*int32_t pt*/);

static int32_t
miku_rsa_set_padding(EVP_PKEY_CTX *ctx) {
  return EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
}
static int32_t
miku_rsa_padding_size() {
  return RSA_PKCS1_PADDING_SIZE;
}

static int32_t
miku_sm2_set_padding(EVP_PKEY_CTX *ctx) {
  return 1;
}
static int32_t
miku_sm2_padding_size() {
  return 0;
}


#ifndef MIN
# define MIN(a, b) ((a) > (b) ? (b) : (a))
#endif

#ifndef MAX
# define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

typedef enum ENC_TYPE {
#define DECLARE_TYPE_ENUM(S, s)  ENC_TYPE_##S,
  ASYMMETRIC_MAP(DECLARE_TYPE_ENUM)
#undef DECLARE_TYPE_ENUM
} ENC_TYPE;

struct MikuAsymmetricHandler {
  ENC_TYPE type;
  EVP_PKEY *pkey;
};

static int32_t
miku_pkey_encrypt_base(EVP_PKEY *pkey,
                       MikuIOContext *ioctx,
                       miku_set_padding_proc set_padding_proc,
                       miku_padding_size_proc padding_size_proc) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (ctx == NULL) {
    return -1;
  }

  if (!set_padding_proc(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  size_t block_size = EVP_PKEY_get_bits(pkey) / 8;
  size_t ds_block = block_size - padding_size_proc();
  int32_t total_write = 0;
  int32_t nwrite = 0;
  uint8_t *inbuf = (uint8_t *)malloc(block_size);
  uint8_t *outbuf = (uint8_t *)malloc(block_size);

  EVP_PKEY_encrypt_init(ctx);

  int32_t ret = -1;
  while (1) {
    size_t nd = miku_io_context_read(ioctx, inbuf, ds_block);
    if (nd == 0) {
      break;
    }

    if (nd < 0) {
      goto finish;
    }

    size_t noutput = block_size;
    nd = EVP_PKEY_encrypt(ctx, outbuf, &noutput, inbuf, nd);
    if (!nd) {
      goto finish;
    }

    int32_t nwrite = miku_io_context_write(ioctx, outbuf, noutput);
    if (nwrite < 0) {
      goto finish;
    }
    total_write += nwrite;
  }

  nwrite = miku_io_context_flush(ioctx);
  if (nwrite < 0) {
    goto finish;
  }

  if (ioctx->t == EIOCONTEXT_TYPE_M2M || ioctx->t == EIOCONTEXT_TYPE_F2M) {
    total_write = nwrite;
  } else {
    total_write += nwrite;
  }

  ret = total_write;
finish:
  EVP_PKEY_CTX_free(ctx);

  free(inbuf);
  free(outbuf);

  return ret;
}

static int32_t
miku_pkey_decrypt_base(EVP_PKEY *pkey,
                       MikuIOContext *ioctx,
                       miku_set_padding_proc set_padding_proc,
                       miku_padding_size_proc padding_size_proc) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (ctx == NULL) {
    return -1;
  }

  if (!set_padding_proc(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  size_t block_size = EVP_PKEY_get_bits(pkey) / 8;
  int32_t total_write = 0;
  int32_t nwrite = 0;
  uint8_t *inbuf = (uint8_t *)malloc(block_size);
  uint8_t *outbuf = (uint8_t *)malloc(block_size);

  EVP_PKEY_decrypt_init(ctx);

  int32_t ret = -1;
  while (1) {
    size_t nd = miku_io_context_read(ioctx, inbuf, block_size);
    if (nd == 0) {
      break;
    }

    if (nd != block_size) {
      goto finish;
    }

    size_t noutput = block_size;
    nd = EVP_PKEY_decrypt(ctx, outbuf, &noutput, inbuf, nd);
    if (!nd) {
      goto finish;
    }

    nwrite = miku_io_context_write(ioctx, outbuf, noutput);
    if (nwrite < 0) {
      goto finish;
    }
    total_write += nwrite;
  }

  nwrite = miku_io_context_flush(ioctx);
  if (nwrite < 0) {
    goto finish;
  }

  if (ioctx->t == EIOCONTEXT_TYPE_M2M || ioctx->t == EIOCONTEXT_TYPE_F2M) {
    total_write = nwrite;
  } else {
    total_write += nwrite;
  }

  ret = total_write;
finish:
  EVP_PKEY_CTX_free(ctx);

  free(inbuf);
  free(outbuf);

  return ret;
}


static MikuAsymmetricHandler *
miku_asymmetric_handler_create_basic(
    ENC_TYPE etype,
    const char *k,
    enum KEY_TYPE kt,
    enum BUFFER_TYPE bt) {
  EVP_PKEY *pkey = NULL;
  BIO *bp = NULL;
  switch (bt) {
   case BUFFER_TYPE_MEMORY:
    bp = BIO_new(BIO_s_mem());
    if (!BIO_write(bp, k, strlen(k))) {
      return NULL;
    }
    break;
   case BUFFER_TYPE_FILE:
   default:
    bp = BIO_new(BIO_s_file());
    if (!BIO_read_filename(bp, k)) {
      return NULL;
    }
  }

  switch (kt) {
   case KEY_TYPE_PRIVATE:
    pkey = PEM_read_bio_PrivateKey(bp, NULL, NULL, NULL);
    break;
   case KEY_TYPE_PUBLIC:
   default:
    pkey = PEM_read_bio_PUBKEY(bp, NULL, NULL, NULL);
  }

  if (pkey == NULL) {
    return NULL;
  }

  MikuAsymmetricHandler *ph =
          (MikuAsymmetricHandler *)malloc(sizeof(MikuAsymmetricHandler));
  ph->pkey = pkey;
  ph->type = etype;
  BIO_free_all(bp);
  return ph;
}

void miku_asymmetric_handler_destroy_basic(MikuAsymmetricHandler *h) {
  if (h != NULL) {
    if (h->pkey != NULL) {
      EVP_PKEY_free(h->pkey);
    }
    free(h);
  }
}


#define ASYMMETRIC_HANDLER_DECLARE(N, n)                                       \
MikuAsymmetricHandler *                                                        \
miku_##n##_handler_create(const char *k,                                       \
                          enum KEY_TYPE kt,                                    \
                          enum BUFFER_TYPE bt) {                               \
  return miku_asymmetric_handler_create_basic(ENC_TYPE_##N, k, kt, bt);        \
}                                                                              \
                                                                               \
int32_t                                                                        \
miku_##n##_handler_destroy(MikuAsymmetricHandler *h) {                         \
  if (h->type != ENC_TYPE_##N) {                                               \
    return -1;                                                                 \
  }                                                                            \
  miku_asymmetric_handler_destroy_basic(h);                                    \
  return 0;                                                                    \
}                                                                              \


// D4 具体定义
#define ASYMMETRIC_D4(S, s, fn, e, et, edt, t)                    \
int32_t fn(MikuAsymmetricHandler *h,                              \
           const uint8_t *din, size_t dlen,                       \
           uint8_t *dout, size_t outlen) {                        \
  if (h->type != ENC_TYPE_##S) {                                  \
    return -1;                                                    \
  }                                                               \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, t, et, edt, din, dlen, dout, outlen)) {           \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_pkey_##e##_base(                             \
      h->pkey, &ioctx,                                            \
      miku_##s##_set_padding, miku_##s##_padding_size);           \
  miku_io_context_uninit(&ioctx);                                 \
  return ret;                                                     \
}

#define ASYMMETRIC_D4_RB(S, s, fn, e, et, edt, t)                 \
int32_t fn(MikuAsymmetricHandler *h,                              \
           const uint8_t *din, size_t dlen,                       \
           ResultBuffer *rb) {                                    \
  if (h->type != ENC_TYPE_##S) {                                  \
    return -1;                                                    \
  }                                                               \
  size_t block_size = EVP_PKEY_get_bits(h->pkey) / 8;             \
  size_t ds_block = block_size - miku_##s##_padding_size();       \
  size_t nblock = (dlen + ds_block - 1) / ds_block;               \
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
  if (d == NULL) {                                                \
    return -1;                                                    \
  }                                                               \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, t, et, edt, din, dlen, rb->d, need_memory)) {     \
    free(d);                                                      \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_pkey_##e##_base(                             \
      h->pkey, &ioctx,                                            \
      miku_##s##_set_padding, miku_##s##_padding_size);           \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    rb->n = ret;                                                  \
    rb->d = d;                                                    \
  } else {                                                        \
    free(d);                                                      \
  }                                                               \
  return ret;                                                     \
}

#define ASYMMETRIC_D4_ARB(S, s, fn, e, et, edt, t)                \
int32_t fn(MikuAsymmetricHandler *h,                              \
           const uint8_t *din, size_t dlen,                       \
           ResultBuffer **rb) {                                   \
  if (h->type != ENC_TYPE_##S) {                                  \
    return -1;                                                    \
  }                                                               \
  ResultBuffer *buf = encrypt_help_result_create();               \
  size_t block_size = EVP_PKEY_get_bits(h->pkey) / 8;             \
  size_t ds_block = block_size - miku_##s##_padding_size();       \
  size_t nblock = (dlen + ds_block - 1) / ds_block;               \
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
        &ioctx, t, et, edt, din, dlen, buf->d, buf->n)) {         \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_pkey_##e##_base(                             \
      h->pkey, &ioctx,                                            \
      miku_##s##_set_padding, miku_##s##_padding_size);           \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    buf->n = ret;                                                 \
    *rb = buf;                                                    \
  } else {                                                        \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
  }                                                               \
  return ret;                                                     \
}


#define ASYMMETRIC_D4_F2M(S, s, fn, e, et, edt, t)                \
int32_t fn(MikuAsymmetricHandler *h,                              \
           const char *fin,                                       \
           uint8_t *dout, size_t outlen) {                        \
  if (h->type != ENC_TYPE_##S) {                                  \
    return -1;                                                    \
  }                                                               \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, t, et, edt,                                       \
        (const uint8_t *)fin, 0, dout, outlen)) {                 \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_pkey_##e##_base(                             \
      h->pkey, &ioctx,                                            \
      miku_##s##_set_padding, miku_##s##_padding_size);           \
  miku_io_context_uninit(&ioctx);                                 \
  return ret;                                                     \
}


#define ASYMMETRIC_D4_F2M_RB(S, s, fn, e, et, edt, t)             \
int32_t fn(MikuAsymmetricHandler *h,                              \
           const char *fin,                                       \
           ResultBuffer *rb) {                                    \
  if (h->type != ENC_TYPE_##S) {                                  \
    return -1;                                                    \
  }                                                               \
  int64_t fsize = miku_encrypt_file_size(fin);                    \
  if (fsize < 0) {                                                \
    return -1;                                                    \
  }                                                               \
  size_t block_size = EVP_PKEY_get_bits(h->pkey) / 8;             \
  size_t ds_block = block_size - miku_##s##_padding_size();       \
  size_t nblock = (fsize + ds_block - 1) / ds_block;              \
  size_t need_memory = nblock * block_size;                       \
  void *d = (void *)malloc(need_memory);                          \
  if (d == NULL) {                                                \
    return -1;                                                    \
  }                                                               \
                                                                  \
  MikuIOContext ioctx;                                            \
  if (!miku_io_context_init(                                      \
        &ioctx, t, et, edt,                                       \
        (const uint8_t *)fin, 0, d, need_memory)) {               \
    free(d);                                                      \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_pkey_##e##_base(                             \
      h->pkey, &ioctx,                                            \
      miku_##s##_set_padding, miku_##s##_padding_size);           \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    rb->n = ret;                                                  \
    rb->d = d;                                                    \
  } else {                                                        \
    free(d);                                                      \
  }                                                               \
  return ret;                                                     \
}

#define ASYMMETRIC_D4_F2M_ARB(S, s, fn, e, et, edt, t)            \
int32_t fn(MikuAsymmetricHandler *h,                              \
           const char *fin,                                       \
           ResultBuffer **rb) {                                   \
  if (h->type != ENC_TYPE_##S) {                                  \
    return -1;                                                    \
  }                                                               \
  int64_t fsize = miku_encrypt_file_size(fin);                    \
  if (fsize < 0) {                                                \
    return -1;                                                    \
  }                                                               \
  ResultBuffer *buf = encrypt_help_result_create();               \
  size_t block_size = EVP_PKEY_get_bits(h->pkey) / 8;             \
  size_t ds_block = block_size - miku_##s##_padding_size();       \
  size_t nblock = (fsize + ds_block - 1) / ds_block;              \
  size_t need_memory = nblock * block_size;                       \
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
        &ioctx, t, et, edt,                                       \
        (const uint8_t *)fin, 0, buf->d, buf->n)) {               \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
    return -1;                                                    \
  }                                                               \
                                                                  \
  int32_t ret = miku_pkey_##e##_base(                             \
      h->pkey, &ioctx,                                            \
      miku_##s##_set_padding, miku_##s##_padding_size);           \
  miku_io_context_uninit(&ioctx);                                 \
  if (ret > 0) {                                                  \
    buf->n = ret;                                                 \
    *rb = buf;                                                    \
  } else {                                                        \
    encrypt_help_result_destroy(buf);                             \
    *rb = NULL;                                                   \
  }                                                               \
  return ret;                                                     \
}


// D3 具体定义
#define ASYMMETRIC_D3_M2M(S, s, n, e, et, edt, t)                    \
  ASYMMETRIC_D4(S, s, n, e, et, edt, t)                              \
  ASYMMETRIC_D4_RB(S, s, n##_rb, e, et, edt, t)                      \
  ASYMMETRIC_D4_ARB(S, s, n##_arb, e, et, edt, t)

#define ASYMMETRIC_D3_F2M(S, s, n, e, et, edt, t)                    \
  ASYMMETRIC_D4_F2M(S, s, n, e, et, edt, t)                          \
  ASYMMETRIC_D4_F2M_RB(S, s, n##_rb, e, et, edt, t)                  \
  ASYMMETRIC_D4_F2M_ARB(S, s, n##_arb, e, et, edt, t)                \

#define ASYMMETRIC_D3_F2F(S, s, fn, e, et, edt, t)                   \
int32_t fn(MikuAsymmetricHandler *h,                                 \
           const char *fin,                                          \
           const char *fout) {                                       \
  if (h->type != ENC_TYPE_##S) {                                     \
    return -1;                                                       \
  }                                                                  \
  MikuIOContext ioctx;                                               \
  if (!miku_io_context_init(&ioctx, t, et, edt,                      \
        (const uint8_t *)fin, 0, (uint8_t *)fout, 0)) {              \
    return -1;                                                       \
  }                                                                  \
                                                                     \
  int32_t ret = miku_pkey_##e##_base(                                \
      h->pkey, &ioctx,                                               \
      miku_##s##_set_padding, miku_##s##_padding_size);              \
  miku_io_context_uninit(&ioctx);                                    \
  return ret;                                                        \
}

#define ASYMMETRIC_D3_M2F(S, s, fn, e, et, edt, t)                   \
int32_t fn(MikuAsymmetricHandler *h,                                 \
           const uint8_t *din, size_t dlen,                          \
           const char *fout){                                        \
  if (h->type != ENC_TYPE_##S) {                                     \
    return -1;                                                       \
  }                                                                  \
  MikuIOContext ioctx;                                               \
  if (!miku_io_context_init(                                         \
        &ioctx, t, et, edt,                                          \
        (const uint8_t *)din, dlen, (uint8_t *)fout, 0)) {           \
    return -1;                                                       \
  }                                                                  \
                                                                     \
  int32_t ret = miku_pkey_##e##_base(                                \
      h->pkey, &ioctx,                                               \
      miku_##s##_set_padding, miku_##s##_padding_size);              \
  miku_io_context_uninit(&ioctx);                                    \
  return ret;                                                        \
}


// D2 输出方式
#define ASYMMETRIC_D2_BIN(S, s, n, e, et, edt)                       \
  ASYMMETRIC_D3_M2M(S, s, n, e, et, edt, EIOCONTEXT_TYPE_M2M)        \
  ASYMMETRIC_D3_F2M(S, s, n##_f2m, e, et, edt, EIOCONTEXT_TYPE_F2M)  \
  ASYMMETRIC_D3_F2F(S, s, n##_f2f, e, et, edt, EIOCONTEXT_TYPE_F2F)  \
  ASYMMETRIC_D3_M2F(S, s, n##_m2f, e, et, edt, EIOCONTEXT_TYPE_M2F)

#define ASYMMETRIC_D2_B64 ASYMMETRIC_D2_BIN
#define ASYMMETRIC_D2_HEX ASYMMETRIC_D2_BIN

// D1,输出格式
#define ASYMMETRIC_D1(S, s, n, e, et)                                 \
  ASYMMETRIC_D2_BIN(S, s, miku_##n, e, et, EDATA_TYPE_BIN)            \
  ASYMMETRIC_D2_B64(S, s, miku_b64_##n, e, et, EDATA_TYPE_BASE64)     \
  ASYMMETRIC_D2_HEX(S, s, miku_hex_##n, e, et, EDATA_TYPE_HEX)

// D0, 通用，加密和解密
#define ASYMMETRIC_D0(S, s)                                           \
  ASYMMETRIC_HANDLER_DECLARE(S, s)                                    \
  ASYMMETRIC_D1(S, s, s##_encrypt, encrypt, ETYPE_ENCRYPT)            \
  ASYMMETRIC_D1(S, s, s##_decrypt, decrypt, ETYPE_DECRYPT)


ASYMMETRIC_MAP(ASYMMETRIC_D0)

#undef ASYMMETRIC_HANDLER_DECLARE
#undef ASYMMETRIC_D0
#undef ASYMMETRIC_D1
#undef ASYMMETRIC_D2_BIN
#undef ASYMMETRIC_D2_B64
#undef ASYMMETRIC_D2_HEX
#undef ASYMMETRIC_D3_M2M
#undef ASYMMETRIC_D3_M2F
#undef ASYMMETRIC_D3_F2M
#undef ASYMMETRIC_D3_F2F
#undef ASYMMETRIC_D4_ARB
#undef ASYMMETRIC_D4_RB
#undef ASYMMETRIC_D4
#undef ASYMMETRIC_D4_F2M
#undef ASYMMETRIC_D4_F2M_RB
#undef ASYMMETRIC_D4_F2M_ARB
