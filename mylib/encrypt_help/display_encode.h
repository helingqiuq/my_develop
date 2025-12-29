#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_DISPLAY_ENCODE_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_DISPLAY_ENCODE_H_

#include "result_buffer.h"
#include "encrypt_common.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus

#define MIKU_DESPLAY_MAPS(XX)  \
  XX(hex)                      \
  XX(b64)                      \

#define DECLARE_DESPLAY_FUNCTION(t) \
  int32_t miku_##t##_encode(        \
      const uint8_t *s,             \
      uint32_t slen,                \
      char *d,                      \
      uint32_t dlen);               \
  int32_t miku_##t##_encode_rb(     \
      const uint8_t *s,             \
      uint32_t slen,                \
      ResultBuffer *rb);            \
  int32_t miku_##t##_encode_arb(    \
      const uint8_t *s,             \
      uint32_t slen,                \
      ResultBuffer **rb);           \
  int32_t miku_##t##_decode(        \
      const char *s,                \
      uint32_t slen,                \
      uint8_t *d,                   \
      uint32_t dlen);               \
  int32_t miku_##t##_decode_rb(     \
      const char *s,                \
      uint32_t slen,                \
      ResultBuffer *rb);            \
  int32_t miku_##t##_decode_arb(    \
      const char *s,                \
      uint32_t slen,                \
      ResultBuffer **rb);           \

MIKU_DESPLAY_MAPS(DECLARE_DESPLAY_FUNCTION)


#undef DECLARE_DESPLAY_FUNCTION










#ifdef __cplusplus
}
#endif  //  __cplusplus

#endif  //  ENCRYPT_HELP_INCLUDE_ENCRYPT_DISPLAY_ENCODE_H_
