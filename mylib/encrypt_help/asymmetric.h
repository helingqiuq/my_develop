#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ASYMMETRIC_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ASYMMETRIC_H_

#include "result_buffer.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus

enum KEY_TYPE {
  KEY_TYPE_PUBLIC = 0,
  KEY_TYPE_PRIVATE = 1,
};

enum BUFFER_TYPE {
  BUFFER_TYPE_MEMORY = 0,
  BUFFER_TYPE_FILE = 1,
};

typedef struct MikuAsymmetricHandler MikuAsymmetricHandler;

// D4 具体定义
#define ASYMMETRIC_D4_M2M(n)                 \
int32_t n(MikuAsymmetricHandler *,           \
          const uint8_t *din, size_t dlen,   \
          uint8_t *dout, size_t outlen);

#define ASYMMETRIC_D4_M2M_RB(n)              \
int32_t n(MikuAsymmetricHandler *,           \
          const uint8_t *din, size_t dlen,   \
          ResultBuffer *rb);

#define ASYMMETRIC_D4_M2M_ARB(n)             \
int32_t n(MikuAsymmetricHandler *,           \
          const uint8_t *din, size_t dlen,   \
          ResultBuffer **rb);

#define ASYMMETRIC_D4_F2M(n)                 \
int32_t n(MikuAsymmetricHandler *,           \
          const char *fin,                   \
          uint8_t *dout, size_t outlen);

#define ASYMMETRIC_D4_F2M_RB(n)              \
int32_t n(MikuAsymmetricHandler *,           \
          const char *fin,                   \
          ResultBuffer *rb);

#define ASYMMETRIC_D4_F2M_ARB(n)             \
int32_t n(MikuAsymmetricHandler *,           \
          const char *fin,                   \
          ResultBuffer **rb);

// D3 具体定义
#define ASYMMETRIC_D3_M2M(n)              \
  ASYMMETRIC_D4_M2M(n)                    \
  ASYMMETRIC_D4_M2M_RB(n##_rb)            \
  ASYMMETRIC_D4_M2M_ARB(n##_arb)          \

#define ASYMMETRIC_D3_F2M(n)              \
  ASYMMETRIC_D4_F2M(n)                    \
  ASYMMETRIC_D4_F2M_RB(n##_rb)            \
  ASYMMETRIC_D4_F2M_ARB(n##_arb)          \

#define ASYMMETRIC_D3_F2F(n)                 \
int32_t n(MikuAsymmetricHandler *,           \
          const char *fin,                   \
          const char *fout);

#define ASYMMETRIC_D3_M2F(n)                 \
int32_t n(MikuAsymmetricHandler *,           \
          const uint8_t *din, size_t dlen,   \
          const char *fout);

// D2 输入，输出方式
#define ASYMMETRIC_D2_BIN(n)                 \
  ASYMMETRIC_D3_M2M(n)                       \
  ASYMMETRIC_D3_F2M(n##_f2m)                 \
  ASYMMETRIC_D3_F2F(n##_f2f)                 \
  ASYMMETRIC_D3_M2F(n##_m2f)

#define ASYMMETRIC_D2_B64 ASYMMETRIC_D2_BIN
#define ASYMMETRIC_D2_HEX ASYMMETRIC_D2_BIN

// D1 输入，输出格式
#define ASYMMETRIC_D1(n)                     \
  ASYMMETRIC_D2_BIN(miku_##n)                \
  ASYMMETRIC_D2_B64(miku_b64_##n)            \
  ASYMMETRIC_D2_HEX(miku_hex_##n)            \

#define ASYMMETRIC_HANDLER_DECLARE(s)                         \
MikuAsymmetricHandler *miku_##s##_handler_create(             \
    const char *k, enum KEY_TYPE kt, enum BUFFER_TYPE bt);    \
int32_t miku_##s##_handler_destroy(MikuAsymmetricHandler *);

// D0, 通用，加密和解密
#define ASYMMETRIC_D0(S, s)             \
  ASYMMETRIC_HANDLER_DECLARE(s)         \
  ASYMMETRIC_D1(s##_encrypt)            \
  ASYMMETRIC_D1(s##_decrypt)            \

#define ASYMMETRIC_MAP(XX)        \
  XX(RSA, rsa)                    \
  XX(SM2, sm2)


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
#undef ASYMMETRIC_D4_M2M
#undef ASYMMETRIC_D4_M2M_RB
#undef ASYMMETRIC_D4_M2M_ARB
#undef ASYMMETRIC_D4_F2M
#undef ASYMMETRIC_D4_F2M_RB
#undef ASYMMETRIC_D4_F2M_ARB

typedef int32_t (*miku_asymmetric_encrypt_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_encrypt_rb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_encrypt_arb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_encrypt_f2m_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_encrypt_f2m_rb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_encrypt_f2m_arb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_encrypt_f2f_arb_fun_t)(
    const char *fin,
    const char *fout);
typedef int32_t (*miku_asymmetric_encrypt_m2f_arb_fun_t)(
    const uint8_t *din, size_t dlen,
    const char *fout);

typedef int32_t (*miku_asymmetric_str_encrypt_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_str_encrypt_rb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_str_encrypt_arb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_str_encrypt_f2m_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_str_encrypt_f2m_rb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_str_encrypt_f2m_arb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_str_encrypt_f2f_arb_fun_t)(
    const char *fin,
    const char *fout);
typedef int32_t (*miku_asymmetric_str_encrypt_m2f_arb_fun_t)(
    const uint8_t *din, size_t dlen,
    const char *fout);

typedef int32_t (*miku_asymmetric_decrypt_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_decrypt_rb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_decrypt_arb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_decrypt_f2m_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_decrypt_f2m_rb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_decrypt_f2m_arb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_decrypt_f2f_arb_fun_t)(
    const char *fin,
    const char *fout);
typedef int32_t (*miku_asymmetric_decrypt_m2f_arb_fun_t)(
    const uint8_t *din, size_t dlen,
    const char *fout);

typedef int32_t (*miku_asymmetric_str_decrypt_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_str_decrypt_rb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_str_decrypt_arb_fun_t)(
    MikuAsymmetricHandler *,
    const uint8_t *din, size_t dlen,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_str_decrypt_f2m_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    uint8_t *dout, size_t outlen);
typedef int32_t (*miku_asymmetric_str_decrypt_f2m_rb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer *rb);
typedef int32_t (*miku_asymmetric_str_decrypt_f2m_arb_fun_t)(
    MikuAsymmetricHandler *,
    const char *fin,
    ResultBuffer **rb);
typedef int32_t (*miku_asymmetric_str_decrypt_f2f_arb_fun_t)(
    const char *fin,
    const char *fout);
typedef int32_t (*miku_asymmetric_str_decrypt_m2f_arb_fun_t)(
    const uint8_t *din, size_t dlen,
    const char *fout);

#ifdef __cplusplus
}
#endif  //  __cplusplus
        //
#endif  // ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ASYMMETRIC_H_
