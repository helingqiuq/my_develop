#include "util/trans_code.h"

#include <iostream>
#include <memory>

namespace miku {
TransCode::TransCode() {
#define TRANSCODE_MAP_CREATE_IV(index, from, to) do {           \
  iv_[TransType::index] = iconv_open(to, from);                 \
  if (iv_[TransType::index] == reinterpret_cast<iconv_t>(-1)) { \
    std::cerr << "create from <" << from                        \
              << "> to <" << to "> failed."                     \
              << std::endl;                                     \
    exit(-1);                                                   \
  }                                                             \
} while(0);

  TRANSCODE_MAP(TRANSCODE_MAP_CREATE_IV)

#undef TRANSCODE_MAP_CREATE_IV
}

TransCode::~TransCode() {
  for (const auto &iv : iv_) {
    iconv_close(iv);
  }
}

const TransCode *TransCode::get() {
  static TransCode c;
  return &c;
}

std::optional<std::string>
TransCode::trans(TransType type,
                 const std::string &s) const {
  const char *pin = s.c_str();
  size_t in_len = s.length();
  size_t in_len_left = in_len;
  size_t out_buf_len = in_len * 3 + 1;
  size_t out_buf_len_left = out_buf_len;
  std::shared_ptr<char []> pbuf(new char[out_buf_len]);
  char *pout = pbuf.get();
  size_t ret = iconv(iv_[type],
                     const_cast<char **>(&pin), &in_len_left,
                     &pout, &out_buf_len_left);
  if (ret == static_cast<size_t>(-1)) {
    return std::nullopt;
  }

  return std::string(pbuf.get(), out_buf_len - out_buf_len_left);
}


std::string
TransCode::try_trans(TransType type, const std::string &s) const {
  auto ret = trans(type, s);
  return ret ? *ret : s;
}

}  // namespace miku
