#include "curl_help.h"

#include <memory>

namespace miku {

struct OnlyInit {
 OnlyInit();
 ~OnlyInit();
};

OnlyInit::OnlyInit() {
  curl_global_init(CURL_GLOBAL_ALL);
}

OnlyInit::~OnlyInit() {
  curl_global_cleanup();
}

size_t
CurlHelp::write_data(void *d, size_t s, size_t n, void *pd) {
  auto *p = reinterpret_cast<CurlHelp *>(pd);
  size_t nd = s * n;
  if (p->wr_callback_ != nullptr) {
    p->wr_callback_(static_cast<const char *>(d), nd);
  }

  return nd;
}

size_t
CurlHelp::read_data(void *d, size_t s, size_t n, void *pd) {
  auto *p = reinterpret_cast<CurlHelp *>(pd);
  size_t nd = s * n;
  if (p->rd_callback_ != nullptr) {
    p->rd_callback_(static_cast<const char *>(d), nd);
  }

  return nd;
}

std::shared_ptr<OnlyInit> p(nullptr);

void
CurlHelp::Initialize() {
  p = std::make_shared<OnlyInit>();
}

CurlHelp::CurlHelp()
    : curl_(curl_easy_init())
    , headers_(nullptr)
    , rd_callback_(nullptr)
    , wr_callback_(nullptr) {
  curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 1L);  // 跟随重定向
}

CurlHelp::~CurlHelp() {
  if (curl_) {
    curl_easy_cleanup(curl_);
  }
  if (headers_ != nullptr) {
    curl_slist_free_all(headers_);
  }
}

void
CurlHelp::SetReadCallback(const CurlHelp::DataCallback &callback) {
  this->rd_callback_ = callback;
  curl_easy_setopt(curl_, CURLOPT_READFUNCTION, read_data);
  curl_easy_setopt(curl_, CURLOPT_READDATA, this);
}

void
CurlHelp::SetWriteCallback(const CurlHelp::DataCallback &callback) {
  this->wr_callback_ = callback;
  curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, write_data);
  curl_easy_setopt(curl_, CURLOPT_WRITEDATA, this);
}

void
CurlHelp::AddHeader(const std::string &h) {
  headers_ = curl_slist_append(headers_, h.c_str());
}

void
CurlHelp::SetUrl(const std::string &url) {
  curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
}

void
CurlHelp::SetKeepAlive(bool b) {
  curl_easy_setopt(curl_, CURLOPT_TCP_KEEPALIVE, b);
}

void
CurlHelp::SetKeepIdle(uint64_t idle) {
  curl_easy_setopt(curl_, CURLOPT_TCP_KEEPIDLE, idle);
}

void
CurlHelp::SetKeepIntvl(uint64_t intvl) {
  curl_easy_setopt(curl_, CURLOPT_TCP_KEEPINTVL, intvl);
}

void
CurlHelp::SetTimeout(uint64_t tt) {
  curl_easy_setopt(curl_, CURLOPT_TIMEOUT, tt);
}

void
CurlHelp::SetTimeoutMs(uint64_t ttms) {
  curl_easy_setopt(curl_, CURLOPT_TIMEOUT_MS, ttms);
}

void
CurlHelp::SetVerbose(bool b) {
  curl_easy_setopt(curl_, CURLOPT_VERBOSE, b);
}

void
CurlHelp::SetForbidReuse(bool b) {
  curl_easy_setopt(curl_, CURLOPT_FORBID_REUSE, b);
}

void
CurlHelp::SetProxy(const std::string &proxy) {
  curl_easy_setopt(curl_, CURLOPT_PROXY, proxy);
}


bool
CurlHelp::Get() {
  if (!curl_) {
    return false;
  }
  curl_easy_setopt(curl_, CURLOPT_POST, 0);

  CURLcode res = curl_easy_perform(curl_);
  return (res == CURLE_OK);
}

bool
CurlHelp::Post(const std::string &d) {
  if (!curl_) {
    return false;
  }

  curl_easy_setopt(curl_, CURLOPT_POST, 1);
  curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, d.c_str());

  CURLcode res = curl_easy_perform(curl_);
  return (res == CURLE_OK);
}

}  // namespace miku
