#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_HASH_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_HASH_H_

#include <stdint.h>

#include "openssl/md5.h"
#include "openssl/sha.h"

#include "result_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus

#define MIKU_DGST_MAPS(XX)                        \
  XX(md5, MD5_DIGEST_LENGTH)                      \
  XX(sha1, SHA_DIGEST_LENGTH)                     \
  XX(sha224, SHA224_DIGEST_LENGTH)                \
  XX(sha256, SHA256_DIGEST_LENGTH)                \
  XX(sha384, SHA384_DIGEST_LENGTH)                \
  XX(sha512, SHA512_DIGEST_LENGTH)                \
  XX(sm3, 32)                                     \


#define DECLARE_DGST_MD_FUNCTION(md, h, out_arg...) \
  int32_t md##_##h(                                 \
      const uint8_t *s,                             \
      uint32_t slen,                                \
      const uint8_t *k,                             \
      uint32_t klen,                                \
      out_arg);                                     \

#define DECLARE_DGST_RT_FUNCTION(md, h, out_arg...)       \
  DECLARE_DGST_MD_FUNCTION(md, h, out_arg)                \
  DECLARE_DGST_MD_FUNCTION(md, h##_rb, ResultBuffer *)    \
  DECLARE_DGST_MD_FUNCTION(md, h##_arb, ResultBuffer **)  \

#define DECLARE_DGST_FUNCTION(h, l)                           \
  DECLARE_DGST_RT_FUNCTION(miku, h, uint8_t *, uint32_t)      \
  DECLARE_DGST_RT_FUNCTION(miku_hex, h, char *, uint32_t)     \
  DECLARE_DGST_RT_FUNCTION(miku_b64, h, char *, uint32_t)     \


MIKU_DGST_MAPS(DECLARE_DGST_FUNCTION)

#undef DECLARE_DGST_FUNCTION
#undef DECLARE_DGST_RT_FUNCTION
#undef DECLARE_DGST_MD_FUNCTION


#ifdef __cplusplus
}  // extern"C"
#endif  //  __cplusplus

#endif  // ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_HASH_H_
