#pragma once

#include <vector>
#include <map>
#include <string>
#include <functional>
#include <tuple>
#include <thread>

#include <stdint.h>

#include "json/json.h"
#include "grpcpp/impl/service_type.h"
#include "openssl/ssl.h"

#include "event.h"
#include "evhttp.h"


namespace miku {

struct ServiceConfig {
  std::string sname;
  std::string saddr;
};

struct HttpServiceConfig {
  std::string host;
  uint32_t port;
  uint32_t parallel;
  uint32_t timeout;
  std::string cert;  // 后续考虑先加载内存再加载文件
  std::string key;  // 后续考虑先加载内存再加载文件
};

using HttpRequestCb = void (*)(struct evhttp_request *, void *);
using HttpRequestReg = std::tuple<std::string, HttpRequestCb, void *>;

struct HttpService {
  HttpServiceConfig http_conf_;
  std::vector<HttpRequestReg> http_regs_;
  SSL_CTX *ssl_ctx_;
  int32_t http_listen_fd_;
  std::vector<struct event_base *> http_bases_;
  std::vector<struct evhttp *> http_httpds_;
  std::vector<std::thread> http_threads_;
};

class Application {
 public:
  Application(const std::string &app_name = std::string(),
              const std::string &server_name = std::string());
  ~Application();

  virtual bool Initialize() = 0;

  void SetTimeZone(const char *tz) const;
  void SetAppName(const std::string &app_name = std::string("unset"),
                  const std::string &server_name = std::string("unset"));
  bool RegisterService(const ServiceConfig &sconf,
                       ::grpc::Service *ptr);

  bool RegisterHttpService(const HttpServiceConfig &conf);
  bool RegisterHttpService(const std::string &sv,
                           const HttpServiceConfig &conf);
  void RegisterHttpCb(const std::string &path, HttpRequestCb cb, void *arg);
  void RegisterHttpCb(const std::string &sv,
                      const std::string &path, HttpRequestCb cb, void *arg);
  void RegisterHttpDefaultCb(HttpRequestCb cb, void *arg);


  void Shutdown();
  void Run();
  const Json::Value &Config() const;

  void Main(int argc, char **argv);
 private:
  std::vector<std::pair<::grpc::Service *,
                        ServiceConfig>> services_;
  std::vector<std::unique_ptr<::grpc::Server>> servers_;
  Json::Value conf_;
  std::string app_name_;
  std::string server_name_;

  std::map<std::string, HttpService> http_services_;
  HttpRequestReg http_default_reg_;

  // 使用ssl时的buffer处理
  static struct bufferevent *ssl_bevcb(struct event_base *base, void *arg);
  SSL_CTX *HttpUseSslContextWithFile(const std::string &cert_file,
                                     const std::string &key_file);
};

}  // namespace miku

