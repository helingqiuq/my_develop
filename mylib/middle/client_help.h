#pragma once

#include "grpc_service_help.h"
#include "util/log.h"
#include "util/statistics.h"
#include "util/time_cost.h"
#include "util/util.h"

// client定义
#ifndef CLIENT_HELP_GRPC_CLIENT_FUN_DECLARE
# define CLIENT_HELP_GRPC_CLIENT_FUN_DECLARE(CN, PN, SV, N, n)            \
  bool N(const PN::N##Req &req, PN::N##Resp *resp);                       \
  miku::grpc_service_help::AsyncResultsWaitable                           \
  Coro##N(const PN::N##Req &req, PN::N##Resp *resp,                       \
          ::grpc::CompletionQueue *cq,                                    \
          miku::coro_task::CoroTaskHelp *task_help);
#endif

namespace miku::client {
DECLARE_MEMBER_CHECK(ret)
DECLARE_MEMBER_CHECK(status)
DECLARE_MEMBER_CHECK(code)

template<typename T>
bool CheckReplySuccess(const T &rsp) {
  if constexpr (miku::client::CheckHas_ret<T>::value) {
    return rsp.ret() == 0;
  } else if constexpr (miku::client::CheckHas_status<T>::value) {
    return rsp.status() == 0;
  } else if constexpr (miku::client::CheckHas_code<T>::value) {
    return rsp.code() == 0;
  } else {
    static_assert(std::false_type::value, "unknow type");
  }
}

template<typename T>
class AutoRpcStatistics {
 public:
  AutoRpcStatistics(const std::string &name,
                    const T &rsp,
                    Statistics *stat = nullptr)
        : name_(name)
        , rsp_(rsp)
        , pstat_(stat)
        , success_(true) {
  }

  ~AutoRpcStatistics() {
    if (pstat_ == nullptr) {
      return;
    }
    if (!success_) {
      pstat_->Add(name_, "failed");
    } else {
      if (CheckReplySuccess(rsp_)) {
        pstat_->Add(name_, "success");
      } else {
        pstat_->Add(name_, "error");
      }
    }

    pstat_->Add(name_, "count");
    pstat_->Add(name_, "cost", ts.TotalCost(), Statistics::AttrValue::AVE);
  }

  void SetCallSuccess(bool succ) {
    success_ = succ;
  }

 private:
  const std::string name_;
  const T &rsp_;
  Statistics *pstat_;
  bool success_;
  TimeCost ts;
};


}

#ifndef CLIENT_HELP_GRPC_CLIENT_FUN_IMPL
# define CLIENT_HELP_GRPC_CLIENT_FUN_IMPL(CN, PN, SV, N, n)               \
bool CN##Client::N(const PN::N##Req &req, PN::N##Resp *resp) {            \
  bool ret = true;                                                        \
  grpc::ClientContext context;                                            \
  if (pstat_ == nullptr) {                                                \
    grpc::Status status = proxy_->N(&context, req, resp);                 \
    if (!status.ok()) {                                                   \
      LogWarn(status.error_code() << ": " << status.error_message());     \
      ret = false;                                                        \
    }                                                                     \
  } else {                                                                \
    miku::client::AutoRpcStatistics cs(#CN "Client::" #N, *resp, pstat_); \
    TimeCost ts;                                                          \
    grpc::Status status = proxy_->N(&context, req, resp);                 \
    if (!status.ok()) {                                                   \
      LogWarn(status.error_code() << ": " << status.error_message());     \
      cs.SetCallSuccess(false);                                           \
      ret = false;                                                        \
    }                                                                     \
  }                                                                       \
                                                                          \
  return ret;                                                             \
}                                                                         \
miku::grpc_service_help::AsyncResultsWaitable                             \
CN##Client::Coro##N(const PN::N##Req &req, PN::N##Resp *resp,             \
                    ::grpc::CompletionQueue *cq,                          \
                    miku::coro_task::CoroTaskHelp *task_help) {           \
  auto *p = new miku::grpc_service_help::CoroCliCallContext<              \
    PN::SV, PN::N##Req, PN::N##Resp>(                                     \
        &proxy_, cq, req, resp,                                           \
        &PN::SV::Stub::Async##N);                                         \
  auto h = p->Proceed();                                                  \
  return {task_help, {h.h_.address()}};                                   \
}
#endif

#ifndef CLIENT_HELP_GRPC_CLIENT_DECLARE
# define CLIENT_HELP_GRPC_CLIENT_DECLARE(CN, PN, SV, M)                   \
namespace miku::client_service {                                          \
class CN##Client final {                                                  \
 private:                                                                 \
  CN##Client(const miku::ClientConfig &conf, Statistics *stat = nullptr); \
  CN##Client(const CN##Client &) = delete;                                \
  CN##Client &operator=(const CN##Client &) = delete;                     \
  miku::ClientProxy<PN::SV> proxy_;                                       \
  Statistics *pstat_;                                                     \
 public:                                                                  \
  ~CN##Client() = default;                                                \
  M(CLIENT_HELP_GRPC_CLIENT_FUN_DECLARE, CN, PN, SV)                      \
  static std::shared_ptr<CN##Client> client_;                             \
  static void Initialize(const miku::ClientConfig &conf,                  \
                         Statistics *stat = nullptr);                     \
};                                                                        \
}
#endif

#ifndef CLIENT_HELP_GRPC_CLIENT_IMPL
# define CLIENT_HELP_GRPC_CLIENT_IMPL(CN, PN, SV, M)                      \
namespace miku::client_service {                                          \
CN##Client::CN##Client(const miku::ClientConfig &conf, Statistics *stat)  \
    : proxy_(conf), pstat_(stat) {}                                       \
std::shared_ptr<CN##Client> CN##Client::client_ = nullptr;                \
void CN##Client::Initialize(const miku::ClientConfig &conf,               \
                            Statistics *stat) {                           \
  client_ = decltype(client_)(new CN##Client(conf, stat));                \
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

//  =========================== end ========================
