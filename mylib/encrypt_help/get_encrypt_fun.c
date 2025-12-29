#include "get_encrypt_fun.h"
#define DECLARE_MIKU_ENCRYPT_FUNS(e, m) \
  miku_##m##_cbc_encrypt,               \
  miku_##m##_cbc_encrypt_np,            \
  miku_##m##_ecb_encrypt,               \
  miku_##m##_ecb_encrypt_np,            \

#define DECLARE_MIKU_DECRYPT_FUNS(e, m) \
  miku_##m##_cbc_decrypt,               \
  miku_##m##_cbc_decrypt_np,            \
  miku_##m##_ecb_decrypt,               \
  miku_##m##_ecb_decrypt_np,            \

#define DECLARE_MIKU_HEX_ENCRYPT_FUNS(e, m) \
  miku_hex_##m##_cbc_encrypt,               \
  miku_hex_##m##_cbc_encrypt_np,            \
  miku_hex_##m##_ecb_encrypt,               \
  miku_hex_##m##_ecb_encrypt_np,            \

#define DECLARE_MIKU_HEX_DECRYPT_FUNS(e, m) \
  miku_hex_##m##_cbc_decrypt,               \
  miku_hex_##m##_cbc_decrypt_np,            \
  miku_hex_##m##_ecb_decrypt,               \
  miku_hex_##m##_ecb_decrypt_np,            \

#define DECLARE_MIKU_B64_ENCRYPT_FUNS(e, m) \
  miku_b64_##m##_cbc_encrypt,               \
  miku_b64_##m##_cbc_encrypt_np,            \
  miku_b64_##m##_ecb_encrypt,               \
  miku_b64_##m##_ecb_encrypt_np,            \

#define DECLARE_MIKU_B64_DECRYPT_FUNS(e, m) \
  miku_b64_##m##_cbc_decrypt,               \
  miku_b64_##m##_cbc_decrypt_np,            \
  miku_b64_##m##_ecb_decrypt,               \
  miku_b64_##m##_ecb_decrypt_np,            \


static miku_encrypt_fun_t s_miku_encrypt_funs[] = {
  MIKU_ENCRYPT_MAP(DECLARE_MIKU_ENCRYPT_FUNS)
};
static miku_decrypt_fun_t s_miku_decrypt_funs[] = {
  MIKU_ENCRYPT_MAP(DECLARE_MIKU_DECRYPT_FUNS)
};
static miku_str_encrypt_fun_t s_miku_hex_encrypt_funs [] = {
  MIKU_ENCRYPT_MAP(DECLARE_MIKU_HEX_ENCRYPT_FUNS)
};
static miku_str_decrypt_fun_t s_miku_hex_decrypt_funs [] = {
  MIKU_ENCRYPT_MAP(DECLARE_MIKU_HEX_DECRYPT_FUNS)
};
static miku_str_encrypt_fun_t s_miku_b64_encrypt_funs [] = {
  MIKU_ENCRYPT_MAP(DECLARE_MIKU_B64_ENCRYPT_FUNS)
};
static miku_str_decrypt_fun_t s_miku_b64_decrypt_funs [] = {
  MIKU_ENCRYPT_MAP(DECLARE_MIKU_B64_DECRYPT_FUNS)
};

#undef DECLARE_MIKU_ENCRYPT_FUNS
#undef DECLARE_MIKU_DECRYPT_FUNS
#undef DECLARE_MIKU_HEX_ENCRYPT_FUNS
#undef DECLARE_MIKU_HEX_DECRYPT_FUNS
#undef DECLARE_MIKU_B64_ENCRYPT_FUNS
#undef DECLARE_MIKU_B64_DECRYPT_FUNS

#define DECLARE_MIKU_DGST_FUNS(h, l) miku_##h,
#define DECLARE_MIKU_HEX_DGST_FUNS(h, l) miku_hex_##h,
#define DECLARE_MIKU_B64_DGST_FUNS(h, l) miku_b64_##h,

static miku_dgst_fun_t s_miku_dgst_funs[] = {
  MIKU_DGST_MAPS(DECLARE_MIKU_DGST_FUNS)
};
static miku_str_dgst_fun_t s_miku_hex_dgst_funs[] = {
  MIKU_DGST_MAPS(DECLARE_MIKU_HEX_DGST_FUNS)
};
static miku_str_dgst_fun_t s_miku_b64_dgst_funs[] = {
  MIKU_DGST_MAPS(DECLARE_MIKU_B64_DGST_FUNS)
};


#undef DECLARE_MIKU_DGST_FUNS
#undef DECLARE_MIKU_HEX_DGST_FUNS
#undef DECLARE_MIKU_B64_DGST_FUNS

// get proc from type
#define DECLARE_GET_FUNS_DECLARE_BASE(type, m, rt)                        \
__attribute__((visibility ("default"))) miku_##type##_fun_t               \
miku_get_##m##_##rt(uint32_t t) {                                         \
  if (t > sizeof(s_miku_##m##_funs) / sizeof(s_miku_##m##_funs[0])) {     \
    return NULL;                                                          \
  } else {                                                                \
    return s_miku_##m##_##rt##s[t];                                       \
  }                                                                       \
}

#define DECLARE_GET_FUNS_DECLARE_RT(type, m)                   \
  DECLARE_GET_FUNS_DECLARE_BASE(type, m, fun)                  \

#define DECLARE_GET_FUNS_DECLARE_PROC(proc)                    \
  DECLARE_GET_FUNS_DECLARE_RT(proc, proc)                      \
  DECLARE_GET_FUNS_DECLARE_RT(str_##proc, hex_##proc)          \
  DECLARE_GET_FUNS_DECLARE_RT(str_##proc, b64_##proc)          \


DECLARE_GET_FUNS_DECLARE_PROC(encrypt)
DECLARE_GET_FUNS_DECLARE_PROC(decrypt)
DECLARE_GET_FUNS_DECLARE_PROC(dgst)

#undef DECLARE_GET_FUNS_DECLARE_PROC
#undef DECLARE_GET_FUNS_DECLARE_RT
#undef DECLARE_GET_FUNS_DECLARE_BASE


