#pragma once

#include <iconv.h>
#include <optional>
#include <string>

#define TRANSCODE_MAP(XX)           \
  XX(GBK_TO_UTF8, "gbk", "utf8")    \
  XX(UTF8_TO_GBK, "utf8", "gbk")    \

namespace miku {
class TransCode {
 public:
  static const TransCode *get();
  enum TransType {
#define TRANSCODE_MAP_DECLARE_ENUM(n, f, t) n,
    TRANSCODE_MAP(TRANSCODE_MAP_DECLARE_ENUM)
      MAX,
#undef TRANSCODE_MAP_DECLARE_ENUM
  };
  std::optional<std::string> trans(TransType type, const std::string &s) const;
  std::string try_trans(TransType type, const std::string &s) const;
 private:
  TransCode();
  ~TransCode(); iconv_t iv_[TransType::MAX];
};
}  // namespace miku
