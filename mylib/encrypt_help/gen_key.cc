#include "gen_key.h"

#include <fstream>

#include "openssl/pem.h"
#include "openssl/bio.h"
#include "openssl/bio.h"

int32_t
miku_generate_key_files(std::ostream *pri,
                        std::ostream *pub,
                        int32_t type,
                        uint32_t bit) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(type, NULL);
  if (ctx == NULL) {
    return -1;
  }

  if (!EVP_PKEY_keygen_init(ctx)) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  if (!EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bit)) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY *pkey = NULL;
  if (!EVP_PKEY_keygen(ctx, &pkey)) {
    EVP_PKEY_CTX_free(ctx);
    return -1;
  }

  EVP_PKEY_CTX_free(ctx);

  // 保存公钥
  BIO *pub_bio = BIO_new(BIO_s_mem());
  if (pub_bio == NULL) {
    return -1;
  }

  if (!PEM_write_bio_PUBKEY(pub_bio, pkey)) {
    BIO_free(pub_bio);
    return -1;
  }

  if (!BIO_flush(pub_bio)) {
    BIO_free(pub_bio);
    return -1;
  }

  BUF_MEM *bptr;
  BIO_get_mem_ptr(pub_bio, &bptr);
  pub->write(reinterpret_cast<char *>(bptr->data), bptr->length);

  BIO_free(pub_bio);

  // 保存私钥
  BIO *priv_bio = BIO_new(BIO_s_mem());
  if (priv_bio == NULL) {
    return -1;
  }

  if (!PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
    BIO_free(priv_bio);
    return -1;
  }

  if (!BIO_flush(priv_bio)) {
    BIO_free(pub_bio);
    return -1;
  }

  BIO_get_mem_ptr(priv_bio, &bptr);
  pri->write(reinterpret_cast<char *>(bptr->data), bptr->length);

  EVP_PKEY_free(pkey);

  return 0;
}

extern "C" int32_t
miku_generate_key_files(const char *pri_file,
                        const char *pub_file,
                        int32_t type,
                        uint32_t bit) {
  std::ofstream fpri(pri_file,
                     std::ios::binary | std::ios::trunc | std::ios::out);
  if (!fpri.is_open()) {
    return -1;
  }
  std::ofstream fpub(pub_file,
                     std::ios::binary | std::ios::trunc | std::ios::out);
  if (!fpub.is_open()) {
    fpri.close();
    return -1;
  }
  auto ret = miku_generate_key_files(&fpri, &fpub, type, bit);
  fpri.close();
  fpub.close();
  return ret;
}
