#include "app_help.h"

#include <fstream>
#include <signal.h>
#include <stdlib.h>

#include "util/log.h"
#include "util/util.h"

#include "grpcpp/ext/proto_server_reflection_plugin.h"
#include "grpcpp/grpcpp.h"
#include "grpcpp/health_check_service_interface.h"
#include "absl/log/initialize.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"

#include "openssl/err.h"
#include "event2/bufferevent_ssl.h"
#include "event2/thread.h"

#if 0
#include "event2/bufferevent.h"
#include "event.h"
#include "event2/http.h"
#include "event2/buffer.h"
#include "event2/bufferevent.h"
#include "event2/bufferevent_ssl.h"
#endif

ABSL_FLAG(std::string, config, "conf/conf.json", "config file");

namespace miku {

Application::Application(const std::string &app_name,
                         const std::string &server_name)
    : app_name_(app_name)
    , server_name_(server_name) {
  ::setenv("TZ", "Asia/Shanghai", 1);

  // 初始化 OpenSSL
  SSL_library_init();
  SSL_load_error_strings();
}

Application::~Application() {
  for (const auto &[p, c] : services_) {
    delete p;
  }

  for (auto &[n, s] : http_services_) {
    if (s.http_listen_fd_ != -1) {
      close(s.http_listen_fd_);
    }

    for (auto &h : s.http_httpds_) {
      if (h != nullptr) {
        evhttp_free(h);
      }
    }

    for (auto &b : s.http_bases_) {
      if (b != nullptr) {
        event_base_free(b);
      }
    }

    if (s.ssl_ctx_ != nullptr) {
      SSL_CTX_free(s.ssl_ctx_);
    }
  }
}

void
Application::SetAppName(const std::string &app_name,
                        const std::string &server_name) {
  app_name_ = app_name;
  server_name_ = server_name;
  std::string log_path = "log/" + app_name_ + "_" + server_name_ + ".log";
  miku::log::set_log_filename(log_path.c_str());
}

bool
Application::RegisterService(const ServiceConfig &sconf,
                                  ::grpc::Service *ptr) {
  services_.push_back({ptr, sconf});
  return true;
}

bool
Application::RegisterHttpService(const HttpServiceConfig &conf) {
  return RegisterHttpService("", conf);  // 默认不设置sv
}

bool
Application::RegisterHttpService(const std::string &sv,
                                 const HttpServiceConfig &conf) {
  http_services_[sv].http_conf_ = conf;
  auto &http_conf = http_services_[sv].http_conf_;
  auto &httpd = http_services_[sv];

  if (http_conf.cert.length() > 0 && http_conf.key.length() > 0) {
    httpd.ssl_ctx_ = HttpUseSslContextWithFile(
        http_conf.cert, http_conf.key);
    if (httpd.ssl_ctx_ == nullptr) {
      LogWarn("load ssl cert failed.");
      return false;
    }
  }

  return http_conf.parallel > 0;  // 成功启动至少需要一个在工作的线程
}

void
Application::RegisterHttpCb(const std::string &path,
                            HttpRequestCb cb,
                            void *arg) {
  RegisterHttpCb("", path, cb, arg);
}

void
Application::RegisterHttpCb(const std::string &sv,
                            const std::string &path,
                            HttpRequestCb cb,
                            void *arg) {
  auto &http_regs = http_services_[sv].http_regs_;
  http_regs.push_back({path, cb, arg});
}


void
Application::RegisterHttpDefaultCb(HttpRequestCb cb,
                                   void *arg) {
  http_default_reg_ = {"", cb, arg};
}


SSL_CTX *
Application::HttpUseSslContextWithFile(const std::string &cert_file,
                                       const std::string &key_file) {
  const SSL_METHOD *method = TLS_server_method();
  SSL_CTX *ctx = SSL_CTX_new(method);
  if (!ctx) {
    LogError("Failed to create SSL_CTX");
    return nullptr;
  }

  // 加载服务端证书
  if (SSL_CTX_use_certificate_chain_file(ctx, cert_file.c_str()) <= 0) {  // 完整验证链
  //  if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(),
  //                                   SSL_FILETYPE_PEM) <= 0) {
    LogError("Failed to load certificate");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return nullptr;
  }

  // 加载服务端私钥
  if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
    LogError("Failed to load private key");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return nullptr;
  }

  // 检查私钥是否和证书匹配
  if (!SSL_CTX_check_private_key(ctx)) {
    LogError("Private key and certificate do not match");
    SSL_CTX_free(ctx);
    return nullptr;
  }

  //  const char *ca_file = "/root/workspace/ca.crt.pem";
  //  if (ca_file && SSL_CTX_load_verify_locations(ctx, ca_file, NULL) <= 0) {
  //    LogWarn("Warning: Failed to load CA file:" << ca_file);
  //  }

  return ctx;
}

void
Application::Run() {
  for (const auto &[s, c] : services_) {
    grpc::ServerBuilder builder;
    //std::string server_address = absl::StrFormat(
    //    "%s:%d", c.saddr.c_str(), c.sport);
    // Listen on the given address without any authentication mechanism.
    builder.AddListeningPort(c.saddr,
                             grpc::InsecureServerCredentials());

    // Register "service" as the instance through which we'll communicate with
    // clients. In this case it corresponds to an *synchronous* service.
    builder.RegisterService(s);
    // Finally assemble the server.
    servers_.push_back(builder.BuildAndStart());

    LogInfo("grpc Service [" << c.sname << "] listening on :" << c.saddr);
  }

  if (http_services_.size() > 0) {
    evthread_use_pthreads();
  }

  for (auto &[n, c] : http_services_) {
    if (c.http_conf_.parallel > 0 && c.http_regs_.size() > 0) {
      c.http_listen_fd_ = miku::create_tcp_lfd(c.http_conf_.host,
                                               c.http_conf_.port);
      if (c.http_listen_fd_ == -1) {
        LogError("http_init failed.");
        exit(1);
      }
      std::string svname =  n.length() > 0 ? n : std::string("<default>");
      if (c.ssl_ctx_ != nullptr) {
        LogInfo("https Server [" << svname << "] listening on :"
                  << c.http_conf_.host << ":" << c.http_conf_.port);
      } else {
        LogInfo("http Service [" << svname << "] listening on :"
                  << c.http_conf_.host << ":" << c.http_conf_.port);
      }

      c.http_bases_.resize(c.http_conf_.parallel);
      c.http_httpds_.resize(c.http_conf_.parallel);
      c.http_threads_.resize(c.http_conf_.parallel);

      for (uint32_t i = 0; i < c.http_conf_.parallel; i++) {
        auto &base = c.http_bases_[i];
        auto &http = c.http_httpds_[i];
        auto &thread = c.http_threads_[i];

        // 创建事件基础设施
        base = event_base_new();
        if (!base) {
          LogError("Could not initialize libevent");
          exit(1);
        }

        // 创建 HTTP 服务器
        http = evhttp_new(base);
        if (!http) {
          LogError("Could not create evhttp");
          exit(1);
        }

        evhttp_accept_socket(http, c.http_listen_fd_);
        if (c.http_conf_.timeout > 0) {
          evhttp_set_timeout(http, c.http_conf_.timeout);
        }

        for (const auto &[p, c, a] : c.http_regs_) {
          std::stringstream ss;
          ss << "/";
          // 设置请求处理回调函数
          if (n.length() == 0) {
            ss << p;
            evhttp_set_cb(http, ss.str().c_str(), c, a);
          } else {
            ss << n << "/" << p;
            evhttp_set_cb(http, ss.str().c_str(), c, a);
          }
        }

        if (std::get<1>(http_default_reg_) != nullptr) {
          const auto &cb = std::get<1>(http_default_reg_);
          const auto &arg = std::get<2>(http_default_reg_);
          evhttp_set_gencb(http, cb, arg);
        }


        if (c.ssl_ctx_ != nullptr) {
          evhttp_set_bevcb(http, ssl_bevcb, c.ssl_ctx_);
        }
        // 开始事件循环
        std::thread t([base]() -> void { event_base_dispatch(base); });
        thread.swap(t);
      }
    }
  }

  for (const auto &p : servers_) {
    // Wait for the server to shutdown. Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    p->Wait();
  }

  for (auto &[n, c] : http_services_) {
    for (auto &p : c.http_threads_) {
      p.join();
    }
  }
}

void
Application::Shutdown() {
  for (const auto &p : servers_) {
    p->Shutdown();
  }

  for (auto &[n, c] : http_services_) {
    for (auto &b : c.http_bases_) {
      event_base_loopexit(b, nullptr);
    }
  }
}

const Json::Value &
Application::Config() const {
  return conf_;
}

void
Application::Main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  grpc::EnableDefaultHealthCheckService(true);
  grpc::reflection::InitProtoReflectionServerBuilderPlugin();
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  auto oconf = miku::json_from_file(absl::GetFlag(FLAGS_config));
  if (!oconf) {
    LogError("load config file failed.");
    return;
  }
  conf_ = std::move(*oconf);

  if (miku::cfg_get_i(conf_, "log.terminal", 0)) {
    miku::log::log_attach_fd(1);
  }

  miku::log::set_log_level(miku::cfg_get_s(conf_, "log.level", "info").c_str());
  if (app_name_.empty()) {
    app_name_ = miku::cfg_get_s(conf_, "app.name", "unset");
  }

  if (server_name_.empty()) {
    server_name_ = miku::cfg_get_s(conf_, "app.server_name", "unset");
  }
  std::string log_path = "log/" + app_name_ + "_" + server_name_ + ".log";
  miku::log::set_log_filename(log_path.c_str());

  if (!Initialize()) {
    LogError("app Initialize failed.");
    return;
  }

  LogInfo("server will to run.");
  Run();
}

struct bufferevent *
Application::ssl_bevcb(struct event_base *base, void *arg) {
  SSL_CTX *ctx = reinterpret_cast<SSL_CTX *>(arg);
  SSL *ssl = SSL_new(ctx);
  return bufferevent_openssl_socket_new(base, -1, ssl,
                                        BUFFEREVENT_SSL_ACCEPTING,
                                        BEV_OPT_CLOSE_ON_FREE);
}

void
Application::SetTimeZone(const char *tz) const {
  ::setenv("TZ", tz, 1);
}

}
