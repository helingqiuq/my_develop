#include "encrypt_common.h"

#include "openssl/bio.h"
#include "openssl/pem.h"

inline uint32_t
miku_dp_encode_bl(uint32_t slen) {
  return slen;
}

inline uint32_t
miku_hex_dp_encode_bl(uint32_t slen) {
  return slen << 1;
}

inline uint32_t
miku_b64_dp_encode_bl(uint32_t slen) {
  return (slen + 2) / 3 * 4;
}

inline uint32_t
miku_dp_decode_bl(uint32_t slen) {
  return slen;
}

inline uint32_t
miku_hex_dp_decode_bl(uint32_t slen) {
  return slen >> 1;
}

inline uint32_t
miku_b64_dp_decode_bl(uint32_t slen) {
  return slen / 4 * 3;
}

__attribute__((visibility ("default"))) int32_t
miku_hex_encode(const uint8_t *s,
                uint32_t slen,
                char *d,
                uint32_t dlen) {
  if (s == NULL || d == NULL || dlen < miku_hex_dp_encode_bl(slen)) {
    return -1;
  }

  static const char v[] = "0123456789abcdef";
  uint32_t i, j;
  for (i = 0, j = 0; i < slen; i++) {
    d[j++] = v[s[i] >> 4 & 0x0f];
    d[j++] = v[s[i] & 0x0f];
  }

  return j;
}

__attribute__((visibility ("default"))) int32_t
miku_hex_decode(const char *s,
                uint32_t slen,
                uint8_t *d,
                uint32_t dlen) {
  if (s == NULL ||
      d == NULL ||
      slen % 2 != 0 ||
      dlen < miku_hex_dp_decode_bl(slen)) {
    return -1;
  }

  memset(d, 0, dlen);

  uint32_t i;
  for (i = 0; i < slen; i++) {
    uint8_t v;
    if (s[i] < 'a') {
      v = s[i] - '0';
    } else {
      v = s[i] - 'a' + 10;
    }

    if (i % 2 == 0) {
      d[i / 2] = v << 4;
    } else {
      d[i / 2] += v;
    }
  }

  return (i + 1) / 2;
}

__attribute__((visibility ("default"))) int32_t
miku_b64_encode(const uint8_t *s,
                uint32_t slen,
                char *d,
                uint32_t dlen) {
  if (s == NULL || d == NULL || dlen < miku_b64_dp_encode_bl(slen)) {
    return -1;
  }

  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) {
    return -1;
  }

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new(BIO_s_mem());
  if (bmem == NULL) {
    BIO_free_all(b64);
    return -1;
  }

  BIO_push(b64, bmem);
  if (BIO_write(b64, s, slen) <= 0) {
    BIO_free_all(b64);
    return -1;
  }

  if (BIO_flush(b64) != 1) {
    BIO_free_all(b64);
    return -1;
  }

  BIO_get_mem_ptr(b64, &bptr);
  uint32_t len = bptr->length;
  memcpy(d, bptr->data, len);
  BIO_free_all(b64);
  return len;
}

__attribute__((visibility ("default"))) int32_t
miku_b64_decode(const char *s,
                uint32_t slen,
                uint8_t *d,
                uint32_t dlen) {
  if (s == NULL ||
      d == NULL ||
      slen % 4 != 0 ||
      dlen < miku_b64_dp_decode_bl(slen)) {
    return -1;
  }

  BIO *b64, *bmem;
  int32_t ret;

  b64 = BIO_new(BIO_f_base64());
  if (b64 == NULL) {
    return -1;
  }

  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bmem = BIO_new_mem_buf(s, slen);
  if (bmem == NULL) {
    BIO_free_all(b64);
    return -1;
  }

  BIO_push(b64, bmem);
  ret = BIO_read(b64, d, dlen);

  BIO_free_all(b64);
  return ret;
}

int64_t
miku_encrypt_file_size(const char *fname) {
  FILE *fp = fopen(fname, "rb");
  if (fp == NULL) {
    return -1;
  }
  if (fseek(fp, SEEK_END, 0) != 0) {
    fclose(fp);
    return -1;
  }

  int64_t s = ftell(fp);
  fclose(fp);
  return s;
}
