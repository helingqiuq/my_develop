#pragma once

#include <vector>
#include <string>
#include <memory>
#include <random>

#include "grpcpp/grpcpp.h"
#include "util/log.h"


namespace miku {

struct ClientConfig {
  std::string sname;
  std::vector<std::string> saddrs;
};

template <typename T>
class ClientProxy {
 public:
  ClientProxy(const ClientConfig &cconf,
              std::shared_ptr<grpc::ChannelCredentials> c = grpc::InsecureChannelCredentials()) {
    // 后续考虑通过name通过名字服务获取list
    for (const auto &a : cconf.saddrs) {
      std::shared_ptr<grpc::Channel> channel(
          grpc::CreateChannel(a, c));
      channels_.push_back(channel);
      stubs_.emplace_back(T::NewStub(channel));
    }

    n_stub_ = channels_.size();
  }
  ~ClientProxy() = default;
  const std::unique_ptr<typename T::Stub> &operator->() const {
    // TODO 这里做选择可以加上权重因素
    std::random_device rd;
    return stubs_[rd() % n_stub_];
  }

 private:
  std::vector<std::unique_ptr<typename T::Stub>> stubs_;  // 这东西可能会使用名字服务更新，后续考虑双buf机制
  std::vector<std::shared_ptr<grpc::Channel>> channels_;  // 这东西可能会使用名字服务更新，后续考虑双buf机制
  uint32_t n_stub_;
};

}  // namespace miku

#ifndef CLIENT_HELP_GRPC_CLIENT_FUN_DECLARE
# define CLIENT_HELP_GRPC_CLIENT_FUN_DECLARE(CN, PN, SV, N, n)            \
  bool N(const PN::N##Req &req, PN::N##Resp *resp);                       \
  std::unique_ptr<grpc::ClientAsyncResponseReader<PN::N##Resp>>           \
  Async##N(const PN::N##Req &req);
#endif


#ifndef CLIENT_HELP_GRPC_CLIENT_FUN_IMPL
# define CLIENT_HELP_GRPC_CLIENT_FUN_IMPL(CN, PN, SV, N, n)               \
bool CN##Client::N(const PN::N##Req &req, PN::N##Resp *resp) {            \
  grpc::ClientContext context;                                            \
  grpc::Status status = proxy_->N(&context, req, resp);                   \
  if (status.ok()) {                                                      \
    return true;                                                          \
  } else {                                                                \
    LogWarn(status.error_code() << ": " << status.error_message());       \
    return false;                                                         \
  }                                                                       \
}                                                                         \
std::unique_ptr<grpc::ClientAsyncResponseReader<PN::N##Resp>>             \
CN##Client::Async##N(const PN::N##Req &req) {                             \
  grpc::ClientContext context;                                            \
  return proxy_->Async##N(&context, req, nullptr);                        \
}
#endif

#ifndef CLIENT_HELP_GRPC_CLIENT_DECLARE
# define CLIENT_HELP_GRPC_CLIENT_DECLARE(CN, PN, SV, M)                   \
namespace miku::client_service {                                          \
class CN##Client final {                                                  \
 private:                                                                 \
  CN##Client(const miku::ClientConfig &conf);                             \
  CN##Client(const CN##Client &) = delete;                                \
  CN##Client &operator=(const CN##Client &) = delete;                     \
  miku::ClientProxy<PN::SV> proxy_;                                       \
 public:                                                                  \
  ~CN##Client() = default;                                                \
  M(CLIENT_HELP_GRPC_CLIENT_FUN_DECLARE, CN, PN, SV)                      \
  static std::shared_ptr<CN##Client> client_;                             \
  static void Initialize(const miku::ClientConfig &conf);                 \
};                                                                        \
}
#endif

#ifndef CLIENT_HELP_GRPC_CLIENT_IMPL
# define CLIENT_HELP_GRPC_CLIENT_IMPL(CN, PN, SV, M)                      \
namespace miku::client_service {                                          \
CN##Client::CN##Client(const miku::ClientConfig &conf) : proxy_(conf) {}  \
std::shared_ptr<CN##Client> CN##Client::client_ = nullptr;                \
void CN##Client::Initialize(const miku::ClientConfig &conf) {             \
  client_ = decltype(client_)(new CN##Client(conf));                      \
}                                                                         \
M(CLIENT_HELP_GRPC_CLIENT_FUN_IMPL, CN, PN, SV)                           \
}
#endif

#ifndef CLIENT_HELP_INITIALIZE
# define CLIENT_HELP_INITIALIZE(CN)           \
  miku::client_service::CN##Client::Initialize
#endif

#ifndef CLIENT_HELP_PROXY
# define CLIENT_HELP_PROXY(CN)                \
  miku::client_service::CN##Client::client_
#endif

