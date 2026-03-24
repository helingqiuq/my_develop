#pragma once

#include <vector>
#include <string>
#include <memory>
#include <random>

#include "grpcpp/grpcpp.h"


namespace miku {

struct ClientConfig {
  std::string sname;
  std::vector<std::string> saddrs;
};

template <typename T>
class ClientProxy {
 public:
   using Stub = T::Stub;
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
  const std::unique_ptr<typename T::Stub> &GetOneStub() const {
    static std::random_device rd;
    return stubs_[rd() % n_stub_];
  }
  const std::unique_ptr<typename T::Stub> &operator->() const {
    return GetOneStub();
  }

 private:
  std::vector<std::unique_ptr<typename T::Stub>> stubs_;  // 这东西可能会使用名字服务更新，后续考虑双buf机制
  std::vector<std::shared_ptr<grpc::Channel>> channels_;  // 这东西可能会使用名字服务更新，后续考虑双buf机制
  uint32_t n_stub_;
};

}  // namespace miku
