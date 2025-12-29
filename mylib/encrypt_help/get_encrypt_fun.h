#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_GET_ENCRYPT_FUN_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_GET_ENCRYPT_FUN_H_

#include "encrypt.h"
#include "asymmetric.h"
#include "hash.h"
#include "display_encode.h"

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus

// encrypt
typedef int32_t (*miku_encrypt_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        uint8_t *d,
        uint32_t dlen);

typedef int32_t (*miku_decrypt_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        uint8_t *d,
        uint32_t dlen);

typedef int32_t (*miku_str_encrypt_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        uint8_t *d,
        uint32_t dlen);

typedef int32_t (*miku_str_decrypt_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        uint8_t *d,
        uint32_t dlen);


typedef int32_t (*miku_encrypt_rb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer *rb);

typedef int32_t (*miku_decrypt_rb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer *rb);

typedef int32_t (*miku_str_encrypt_rb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer *rb);

typedef int32_t (*miku_str_decrypt_rb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer *rb);

typedef int32_t (*miku_encrypt_arb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer **rb);

typedef int32_t (*miku_decrypt_arb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer **rb);

typedef int32_t (*miku_str_encrypt_arb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer **rb);

typedef int32_t (*miku_str_decrypt_arb_fun_t)(
        const uint8_t *s,
        uint32_t slen,
        const uint8_t *p,
        uint32_t plen,
        const uint8_t *v,
        uint32_t vlen,
        ResultBuffer **rb);

// dest
typedef int32_t (*miku_dgst_fun_t)(
    const uint8_t *s,
    uint32_t slen,
    const uint8_t *k,
    uint32_t klen,
    uint8_t *out,
    uint32_t outLen);

typedef int32_t (*miku_str_dgst_fun_t)(
    const uint8_t *s,
    uint32_t slen,
    const uint8_t *k,
    uint32_t klen,
    char *out,
    uint32_t outLen);

#define DECLARE_GET_FUNS_BASE(type, m, rt)                                \
  miku_##type##_fun_t miku_get_##m##_##rt(uint32_t type);

#define DECLARE_GET_FUNS_RT(type, m)                                      \
  DECLARE_GET_FUNS_BASE(type, m, fun)                                     \

#define DECLARE_GET_FUNS_PROC(proc)                                       \
  DECLARE_GET_FUNS_RT(proc, proc)                                         \
  DECLARE_GET_FUNS_RT(str_##proc, hex_##proc)                             \
  DECLARE_GET_FUNS_RT(str_##proc, b64_##proc)                             \


DECLARE_GET_FUNS_PROC(encrypt)
DECLARE_GET_FUNS_PROC(decrypt)
DECLARE_GET_FUNS_PROC(dgst)

#undef DECLARE_GET_FUNS_PROC
#undef DECLARE_GET_FUNS_RT
#undef DECLARE_GET_FUNS_BASE

#ifdef __cplusplus
}  // extern"C"
#endif  //  __cplusplus

#endif  // ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_GET_ENCRYPT_FUN_H_
