#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ENCRYPT_COMMON_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ENCRYPT_COMMON_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus


uint32_t miku_dp_encode_bl(uint32_t slen);
uint32_t miku_hex_dp_encode_bl(uint32_t slen);
uint32_t miku_b64_dp_encode_bl(uint32_t slen);
uint32_t miku_dp_decode_bl(uint32_t slen);
uint32_t miku_hex_dp_decode_bl(uint32_t slen);
uint32_t miku_b64_dp_decode_bl(uint32_t slen);

int32_t miku_hex_encode(const uint8_t *s, uint32_t slen,
                        char *d, uint32_t dlen);
int32_t miku_hex_decode(const char *s, uint32_t slen,
                        uint8_t *d, uint32_t dlen);
int32_t miku_b64_encode(const uint8_t *s, uint32_t slen,
                        char *d, uint32_t dlen);
int32_t miku_b64_decode(const char *s, uint32_t slen,
                        uint8_t *d, uint32_t dlen);
int64_t miku_encrypt_file_size(const char *fname);

#ifdef __cplusplus
}  // extern"C"
#endif  //  __cplusplus

#endif  // ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_ENCRYPT_COMMON_H_
