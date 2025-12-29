#include "hash.h"

#include "encrypt_common.h"

#include "openssl/evp.h"
#include "openssl/hmac.h"

// 哈希
#define DECLARE_DGST_BASE(md, h, l)                       \
__attribute__((visibility ("default"))) int32_t           \
md##_##h(const uint8_t *s,                                \
         uint32_t slen,                                   \
         const uint8_t *k,                                \
         uint32_t klen,                                   \
         char *out,                                       \
         uint32_t outlen) {                               \
  uint8_t *buf = (uint8_t *)malloc(l);                    \
  if (buf == NULL) {                                      \
    return -1;                                            \
  }                                                       \
  int32_t len = miku_##h(s, slen, k, klen, buf, l);       \
  if (len < 0) {                                          \
    free(buf);                                            \
    return -1;                                            \
  }                                                       \
                                                          \
  len = md##_encode(buf, len, out, outlen);               \
  free(buf);                                              \
                                                          \
  return len;                                             \
}                                                         \

#define DECLARE_DGST_RB(md, h, l)                         \
__attribute__((visibility ("default"))) int32_t           \
md##_##h##_arb(const uint8_t *s,                          \
               uint32_t slen,                             \
               const uint8_t *k,                          \
               uint32_t klen,                             \
               ResultBuffer **rb) {                       \
  if (rb == NULL) {                                       \
    return -1;                                            \
  }                                                       \
  *rb = encrypt_help_result_create();                     \
  if (*rb == NULL) {                                      \
    return -1;                                            \
  }                                                       \
  int32_t ret = md##_##h##_rb(s, slen, k, klen, *rb);     \
  if (ret <= 0) {                                         \
    encrypt_help_result_destroy(*rb);                     \
    *rb = NULL;                                           \
  }                                                       \
  return ret;                                             \
}                                                         \

#define DECLARE_DGST_ARB(md, h, l)                        \
__attribute__((visibility ("default"))) int32_t           \
md##_##h##_rb(const uint8_t *s,                           \
              uint32_t slen,                              \
              const uint8_t *k,                           \
              uint32_t klen,                              \
              ResultBuffer *rb) {                         \
  if (rb == NULL) {                                       \
    return -1;                                            \
  }                                                       \
  int32_t n = md##_dp_encode_bl(l);                       \
  void *d = malloc(n);                                    \
  if (d == NULL) {                                        \
    return -1;                                            \
  }                                                       \
  int32_t ret = md##_##h(s, slen, k, klen, d, n);         \
  if (ret > 0) {                                          \
    rb->n = ret;                                          \
    rb->d = d;                                            \
  } else {                                                \
    free(d);                                              \
  }                                                       \
  return ret;                                             \
}                                                         \


#define DECLARE_DGST_FUNCTION_PROC(h, l)                  \
__attribute__((visibility ("default"))) int32_t           \
miku_##h(const uint8_t *s,                                \
         uint32_t slen,                                   \
         const uint8_t *k,                                \
         uint32_t klen,                                   \
         uint8_t *out,                                    \
         uint32_t outlen) {                               \
  if (s == NULL || out == NULL || outlen < l) {           \
    return -1;                                            \
  }                                                       \
                                                          \
  if (k == NULL || klen == 0) {                           \
    EVP_Digest(s, slen, out, NULL, EVP_##h(), NULL);      \
  } else {                                                \
    HMAC(EVP_##h(), k, klen, s, slen, out, NULL);         \
  }                                                       \
  return l;                                               \
}                                                         \
DECLARE_DGST_ARB(miku, h, l)                              \
DECLARE_DGST_RB(miku, h, l)                               \
DECLARE_DGST_BASE(miku_hex, h, l)                         \
DECLARE_DGST_ARB(miku_hex, h, l)                          \
DECLARE_DGST_RB(miku_hex, h, l)                           \
DECLARE_DGST_BASE(miku_b64, h, l)                         \
DECLARE_DGST_ARB(miku_b64, h, l)                          \
DECLARE_DGST_RB(miku_b64, h, l)                           \

MIKU_DGST_MAPS(DECLARE_DGST_FUNCTION_PROC)

#undef DECLARE_DGST_FUNCTION_PROC
#undef DECLARE_DGST_RB
#undef DECLARE_DGST_ARB
#undef DECLARE_DGST_BASE
