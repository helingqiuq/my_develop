#pragma once

#include <stdint.h>

#include "openssl/rsa.h"
#include "openssl/evp.h"

#ifdef __cplusplus
#include <sstream>

int32_t miku_generate_key_files(std::ostream *pri,
                                std::ostream *pub,
                                int32_t type = EVP_PKEY_RSA,
                                uint32_t bit = 2048);

extern "C" {
#endif  //  __cplusplus

int32_t miku_generate_key_files(const char *pri_file,
                                const char *pub,
                                int32_t type,
                                uint32_t bit);

#ifdef  __cplusplus
}  // extern "C"
#endif  // __cplusplus
