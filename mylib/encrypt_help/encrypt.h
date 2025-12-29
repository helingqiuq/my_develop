#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ENCRYPT_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ENCRYPT_H_

#include "result_buffer.h"
#include "display_encode.h"
#include "hash.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus

// D5 具体定义
#define ENCRYPT_D5_M2M(n)                              \
int32_t n(const uint8_t *d, uint32_t dlen,             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          uint8_t *dout, uint32_t outlen);             \
int32_t n##_np(const uint8_t *d, uint32_t dlen,        \
               const uint8_t *p, uint32_t plen,        \
               const uint8_t *v, uint32_t vlen,        \
               uint8_t *dout, uint32_t outlen);        \
int32_t n##_padding(const uint8_t *d, uint32_t dlen,   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    uint8_t *dout, uint32_t outlen,    \
                    int32_t padding);

#define ENCRYPT_D5_M2M_RB(n)                           \
int32_t n(const uint8_t *d, uint32_t dlen,             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          ResultBuffer *rb);                           \
int32_t n##_np(const uint8_t *d, uint32_t dlen,        \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          ResultBuffer *rb);                           \
int32_t n##_padding(const uint8_t *d, uint32_t dlen,   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    ResultBuffer *rb,                  \
                    int32_t padding);

#define ENCRYPT_D5_M2M_ARB(n)                          \
int32_t n(const uint8_t *d, uint32_t dlen,             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          ResultBuffer **rb);                          \
int32_t n##_np(const uint8_t *d, uint32_t dlen,        \
               const uint8_t *p, uint32_t plen,        \
               const uint8_t *v, uint32_t vlen,        \
               ResultBuffer **rb);                     \
int32_t n##_padding(const uint8_t *d, uint32_t dlen,   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    ResultBuffer **rb,                 \
                    int32_t padding);

#define ENCRYPT_D5_F2M(n)                              \
int32_t n(const char *fin,                             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          uint8_t *dout, uint32_t outlen);             \
int32_t n##_np(const char *fin,                        \
               const uint8_t *p, uint32_t plen,        \
               const uint8_t *v, uint32_t vlen,        \
               uint8_t *dout, uint32_t outlen);        \
int32_t n##_padding(const char *fin,                   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    uint8_t *dout, uint32_t outlen,    \
                    int32_t padding);

#define ENCRYPT_D5_F2M_RB(n)                           \
int32_t n(const char *fin,                             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          ResultBuffer *rb);                           \
int32_t n##_np(const char *fin,                        \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          ResultBuffer *rb);                           \
int32_t n##_padding(const char *fin,                   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    ResultBuffer *rb ,                 \
                    int32_t padding);

#define ENCRYPT_D5_F2M_ARB(n)                          \
int32_t n(const char *fin,                             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          ResultBuffer **rb);                          \
int32_t n##_np(const char *fin,                        \
               const uint8_t *p, uint32_t plen,        \
               const uint8_t *v, uint32_t vlen,        \
               ResultBuffer **rb);                     \
int32_t n##_padding(const char *fin,                   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    ResultBuffer **rb,                 \
                    int32_t padding);

// D4 具体定义
#define ENCRYPT_D4_M2M(n)               \
  ENCRYPT_D5_M2M(n)                     \
  ENCRYPT_D5_M2M_RB(n##_rb)             \
  ENCRYPT_D5_M2M_ARB(n##_arb)

#define ENCRYPT_D4_F2M(n)               \
  ENCRYPT_D5_F2M(n)                     \
  ENCRYPT_D5_F2M_RB(n##_rb)             \
  ENCRYPT_D5_F2M_ARB(n##_arb)


#define ENCRYPT_D4_M2F(n)                              \
int32_t n(const uint8_t *d, uint32_t dlen,             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          const char *fout);                           \
int32_t n##_np(const uint8_t *d, uint32_t dlen,        \
               const uint8_t *p, uint32_t plen,        \
               const uint8_t *v, uint32_t vlen,        \
               const char *fout);                      \
int32_t n##_padding(const uint8_t *d, uint32_t dlen,   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    const char *fout,                  \
                    int32_t padding);

#define ENCRYPT_D4_F2F(n)                              \
int32_t n(const char *fin,                             \
          const uint8_t *p, uint32_t plen,             \
          const uint8_t *v, uint32_t vlen,             \
          const char *fout);                           \
int32_t n##_np(const char *fin,                        \
               const uint8_t *p, uint32_t plen,        \
               const uint8_t *v, uint32_t vlen,        \
               const char *fout);                      \
int32_t n##_padding(const char *fin,                   \
                    const uint8_t *p, uint32_t plen,   \
                    const uint8_t *v, uint32_t vlen,   \
                    const char *fout,                  \
                    int32_t padding);

// D3 输入，输出方式
#define ENCRYPT_D3_BIN(n)               \
  ENCRYPT_D4_M2M(n)                     \
  ENCRYPT_D4_F2M(n##_f2m)               \
  ENCRYPT_D4_M2F(n##_m2f)               \
  ENCRYPT_D4_F2F(n##_f2f)

#define ENCRYPT_D3_HEX ENCRYPT_D3_BIN
#define ENCRYPT_D3_B64 ENCRYPT_D3_BIN


// D2 输入，输出格式
#define ENCRYPT_D2(n)                   \
  ENCRYPT_D3_BIN(miku_##n)              \
  ENCRYPT_D3_HEX(miku_hex_##n)          \
  ENCRYPT_D3_B64(miku_b64_##n)          \

// D1, 通用，加密和解密
#define ENCRYPT_D1(n)                   \
  ENCRYPT_D2(n##_encrypt)               \
  ENCRYPT_D2(n##_decrypt)               \


// D0, 通用，加解密模式
#define ENCRYPT_D0(S, s)                \
  ENCRYPT_D1(s##_cbc)                   \
  ENCRYPT_D1(s##_ecb)                   \


#define MIKU_ENCRYPT_MAP(XX)            \
  XX(AES_128, aes_128)                  \
  XX(AES_192, aes_192)                  \
  XX(AES_256, aes_256)                  \
  XX(SM4, sm4)                          \
  XX(DES, des)                          \

MIKU_ENCRYPT_MAP(ENCRYPT_D0)


#undef ENCRYPT_D5_M2M
#undef ENCRYPT_D5_M2M_RB
#undef ENCRYPT_D5_M2M_ARB
#undef ENCRYPT_D5_F2M
#undef ENCRYPT_D5_F2M_RB
#undef ENCRYPT_D5_F2M_ARB
#undef ENCRYPT_D4_M2M
#undef ENCRYPT_D4_F2M
#undef ENCRYPT_D4_M2F
#undef ENCRYPT_D4_F2F
#undef ENCRYPT_D3_BIN
#undef ENCRYPT_D3_B64
#undef ENCRYPT_D3_HEX
#undef ENCRYPT_D2
#undef ENCRYPT_D1
#undef ENCRYPT_D0


#ifdef __cplusplus
}
#endif  //  __cplusplus

#endif  //  ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ENCRYPT_H_
