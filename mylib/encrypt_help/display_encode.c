#include "display_encode.h"

#include <string.h>
#include <stdlib.h>

#define MIKU_DESPLAY_RB_BASE(m, proc, st) int32_t       \
miku_##m##_##proc##_rb(const st s,                      \
                       uint32_t slen,                   \
                       ResultBuffer *rb) {              \
  if (rb == NULL) {                                     \
    return -1;                                          \
  }                                                     \
                                                        \
  int32_t len = miku_##m##_dp_##proc##_bl(slen);        \
  void *d = malloc(len);                                \
  if (d == NULL) {                                      \
    return -1;                                          \
  }                                                     \
                                                        \
  int32_t ret = miku_##m##_##proc(s, slen, d, len);     \
  if (ret > 0) {                                        \
    rb->n = ret;                                        \
    rb->d = d;                                          \
  } else {                                              \
    free(d);                                            \
  }                                                     \
  return ret;                                           \
}                                                       \

#define MIKU_DESPLAY_ARB_BASE(m, proc, st) int32_t      \
miku_##m##_##proc##_arb(const st s,                     \
                        uint32_t slen,                  \
                        ResultBuffer **rb) {            \
  if (rb == NULL) {                                     \
    return -1;                                          \
  }                                                     \
                                                        \
  *rb = encrypt_help_result_create();                   \
  if (*rb == NULL) {                                    \
    return -1;                                          \
  }                                                     \
                                                        \
  int32_t ret = miku_##m##_##proc##_rb(s, slen, *rb);   \
  if (ret <= 0) {                                       \
    encrypt_help_result_destroy(*rb);                   \
    *rb = NULL;                                         \
  }                                                     \
                                                        \
  return ret;                                           \
}                                                       \

#define MIKU_DESPLAY_ST_PROC(m)                     \
  MIKU_DESPLAY_RB_BASE(m, encode, uint8_t *)        \
  MIKU_DESPLAY_RB_BASE(m, decode, char *)           \
  MIKU_DESPLAY_ARB_BASE(m, encode, uint8_t *)       \
  MIKU_DESPLAY_ARB_BASE(m, decode, char *)          \


MIKU_DESPLAY_MAPS(MIKU_DESPLAY_ST_PROC)
