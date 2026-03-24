#pragma once

#include <grpcpp/grpcpp.h>
#include <grpcpp/completion_queue.h>

#include <functional>
#include <coroutine>
#include <thread>

#include "util/coro_task.h"
#include "util/util.h"
#include "client_proxy.h"


namespace miku {

struct ServiceConfig {
  std::string sname;
  std::string saddr;
  uint32_t parallel = 1;
};

}  // namespace miku

namespace miku::grpc_service_help {

using CoroTraits = miku::coro_task::CoroTaskHelp::Traits;
using AsyncResultsWaitable = miku::coro_task::CoroTaskHelp::CoAwait;


struct ServerBase {
  explicit ServerBase(const miku::ServiceConfig &conf,
                      void *context,
                      uint32_t io_thread_cnt = 1,
                      uint32_t work_thread_cnt = 1);
  virtual ~ServerBase();
  void Shutdown();
  void Wait();

  virtual void Run() = 0;
  inline miku::coro_task::CoroTaskHelp *TaskHelp() { return &coro_task_help_;}
  inline void *Context() { return context_; }

 protected:
  std::vector<std::thread> tworks_;
  std::vector<std::unique_ptr<::grpc::ServerCompletionQueue>> cq_;
  std::unique_ptr<::grpc::Server> server_;
  const miku::ServiceConfig conf_;
  void *context_;
  const uint32_t io_thread_cnt_;
  miku::coro_task::CoroTaskHelp coro_task_help_;
  bool exit_;
};

struct CoroCallContextBase {
  int32_t type_;
  CoroTraits::promise_type *promise_;
  virtual CoroTraits Proceed() = 0;
  enum CallStatus {
    INIT,
    SVR_CREATE,
    SVR_PROCESS,
    SVR_FINISH,
    CLI_CREATE,
    CLI_PROCESS,
    CLI_FINISH,
  } status_;

  explicit CoroCallContextBase(int32_t type,
                               CoroTraits::promise_type *promise_,
                               CoroCallContextBase::CallStatus status);
};

template <typename SVR, typename REQ, typename RESP>
struct CoroSvrCallContext : public CoroCallContextBase {
  using GetReqProc = void (SVR::*)(::grpc::ServerContext *,
                                   REQ *,
                                   ::grpc::ServerAsyncResponseWriter<RESP> *,
                                   ::grpc::CompletionQueue *n,
                                   ::grpc::ServerCompletionQueue *,
                                   void *);

  CoroSvrCallContext(int32_t type,
                     ServerBase *server_base,
                     SVR *service,
                     ::grpc::ServerCompletionQueue *cq,
                     GetReqProc proc)
        : CoroCallContextBase(type, nullptr, SVR_CREATE)
        , server_base_(server_base)
        , service_(service)
        , cq_(cq)
        , responder_(&ctx_) {
    (service_->*proc)(&ctx_, &request_, &responder_, cq_, cq_, this);
  }
  virtual ~CoroSvrCallContext() {}

  virtual CoroTraits Process(::grpc::ServerContext &ctx,
                             const REQ &req,
                             RESP *reply) = 0;

  virtual CoroTraits Proceed() override {
    co_yield &this->promise_;
    this->status_ = SVR_PROCESS;

    co_await server_base_->TaskHelp()->DoTask(
            std::bind(&CoroSvrCallContext::Process,
                      this,
                      std::ref(ctx_),
                      std::cref(request_),
                      &reply_));

    responder_.Finish(reply_, ::grpc::Status::OK, this);
    this->status_ = SVR_FINISH;

    co_await AsyncResultsWaitable();

    delete this;
  }

  inline ::grpc::CompletionQueue *SvrCQ() { return cq_;}
  template <typename T>
  inline T *SvrContext() {
    return reinterpret_cast<T *>(server_base_->Context());
  }
  inline miku::coro_task::CoroTaskHelp *SvrTaskHelp() {
    return server_base_->TaskHelp();
  }

 protected:
  ServerBase *server_base_;
  SVR *service_;
  ::grpc::ServerCompletionQueue *cq_;
  ::grpc::ServerContext ctx_;

  REQ request_;
  RESP reply_;

  ::grpc::ServerAsyncResponseWriter<RESP> responder_;
};


template <typename SVR, typename REQ, typename RESP>
struct CoroCliCallContext : public CoroCallContextBase {
  using CallProc = std::unique_ptr<::grpc::ClientAsyncResponseReader<RESP>>
                        (SVR::Stub::*)(::grpc::ClientContext *,
                                       const REQ &,
                                       ::grpc::CompletionQueue *);

  CoroCliCallContext(miku::ClientProxy<SVR> *proxy,
                     ::grpc::CompletionQueue *cq,
                     const REQ &req,
                     RESP *resp,
                     CallProc proc)
        : CoroCallContextBase(-1, nullptr, CLI_CREATE)
        , reply_(resp)
        , rpc_((proxy->GetOneStub().get()->*proc)(&ctx_, req, cq)) {
    //rpc->Finish(&reply, &status, (void*)1);
  }
  virtual ~CoroCliCallContext() {}

  virtual CoroTraits Proceed() override {
    co_yield &this->promise_;
    this->status_ = CLI_PROCESS;

    rpc_->Finish(reply_, &grpc_status_, this);
    this->status_ = SVR_FINISH;
    co_await AsyncResultsWaitable();

    miku::coro_task::CoroRet ret;
    if (grpc_status_.ok()) {
      ret = miku::coro_task::CoroRetTrue;
    } else {
      ret = miku::coro_task::CoroRetFalse;
    }
    delete this;
    co_return ret;
  }

 protected:
  RESP *reply_;
  ::grpc::ClientContext ctx_;
  ::grpc::Status grpc_status_;
  std::unique_ptr<::grpc::ClientAsyncResponseReader<RESP>> rpc_;
};



template <typename SVR>
struct ServerTp : public ServerBase {
  using ServerBase::ServerBase;
  virtual void Run() override {
    ::grpc::ServerBuilder builder;
    std::vector<std::string> addrs = miku::split(conf_.saddr, ',');
    for (const auto &addr : addrs) {
      builder.AddListeningPort(addr, grpc::InsecureServerCredentials());
    }
    builder.RegisterService(&service_);

    cq_.resize(io_thread_cnt_);
    for (uint32_t i = 0; i < io_thread_cnt_; i++) {
      cq_[i] = builder.AddCompletionQueue();
    }
    server_ = builder.BuildAndStart();
    std::cout << "Server listening on " << conf_.saddr << std::endl;
    HandleRpcs();
  }

  void virtual CreateAllRequest(SVR *s,
                                ::grpc::ServerCompletionQueue *cq_) = 0;
  void virtual CreateOneRequest(int32_t type,
                                SVR *s,
                                ::grpc::ServerCompletionQueue *cq_) = 0;
  void HandleRpcs() {
    auto proc = [&](uint32_t i) -> void {
      CreateAllRequest(&service_, cq_[i].get());
      void *tag;  // uniquely identifies a request.
      bool ok;
      while (!exit_) {
        cq_[i]->Next(&tag, &ok);
        if (!ok) {
          continue;
        }

        auto *pcalldata = reinterpret_cast<CoroCallContextBase *>(tag);
        switch (pcalldata->status_) {
         case CoroCallContextBase::SVR_CREATE:
          CreateOneRequest(pcalldata->type_, &service_, cq_[i].get());
          {
            auto h = pcalldata->Proceed();
            h.h_.resume();
          }
          break;
         case CoroCallContextBase::SVR_FINISH:
         case CoroCallContextBase::CLI_FINISH:
          {
            auto h = std::coroutine_handle<
              CoroTraits::promise_type>::from_promise(*pcalldata->promise_);
            h.resume();
          }
          break;
         default:
          break;
        }
      }
    };

    tworks_.resize(io_thread_cnt_);
    for (uint32_t i = 0; i < io_thread_cnt_; i++) {
      std::thread t(proc, i);
      tworks_[i].swap(t);
    }
  }
 protected:
  SVR service_;
};


}  // namespace miku::grpc_service_help



//  协程服务端定义代码

#ifndef SERVICE_HELP_GRPC_CORO_FUN_DECLARE
# define SERVICE_HELP_GRPC_CORO_FUN_DECLARE(CN, PN, SV, N, n)                 \
struct N##Call final :                                                        \
    public miku::grpc_service_help::CoroSvrCallContext<                       \
      PN::SV::AsyncService, PN::N##Req, PN::N##Resp> {                        \
  N##Call(int32_t type,                                                       \
          ServerBase *server_base,                                            \
          PN::SV::AsyncService *service,                                      \
          ::grpc::ServerCompletionQueue *cq);                                 \
  virtual ~N##Call();                                                         \
  miku::grpc_service_help::CoroTraits Process(                                \
      ::grpc::ServerContext &ctx,                                             \
      const PN::N##Req &request,                                              \
      PN::N##Resp *reply) override;                                           \
};
#endif  // ifndef SERVICE_HELP_GRPC_CORO_FUN_DECLARE


#ifndef SERVICE_HELP_GRPC_CORO_FUN_IMPL
# define SERVICE_HELP_GRPC_CORO_FUN_IMPL(CN, PN, SV, N, n)                    \
CN##CoroServer::N##Call::N##Call(int32_t type,                                \
                     ServerBase *server_base,                                 \
                     PN::SV::AsyncService *service,                           \
                     ::grpc::ServerCompletionQueue *cq)                       \
  : miku::grpc_service_help::CoroSvrCallContext<                              \
    PN::SV::AsyncService, PN::N##Req, PN::N##Resp>(                           \
      type, server_base, service, cq, &PN::SV::AsyncService::Request##N) {}   \
CN##CoroServer::N##Call::~N##Call() {}                                        \

#endif // ifndef SERVICE_HELP_GRPC_CORO_FUN_IMP




// 服务定义相关

// enum定义
#ifndef SERVICE_HELP_GRPC_CORO_REQUEST_ENUM
# define SERVICE_HELP_GRPC_CORO_REQUEST_ENUM(CN, PN, SV, N, n) N,
#endif

// CreateOneRequest 实现
#define SERVICE_HELP_GRPC_CORO_REQUEST_CREATE_ONE(CN, PN, SV, N, n)           \
 case N: new N##Call(type, this, s, cq_); break;


// CreateAllRequest 实现
#define SERVICE_HELP_GRPC_CORO_REQUEST_CREATE_ALL(CN, PN, SV, N, n)           \
 new N##Call(N, this, s, cq_);


#ifndef SERVICE_HELP_GRPC_CORO_SERVICE_DECLARE
# define SERVICE_HELP_GRPC_CORO_SERVICE_DECLARE(CN, PN, SV, M)                \
namespace miku::coro_service {                                                \
class CN##CoroServerContext;                                                  \
class CN##CoroServer final :                                                  \
    public miku::grpc_service_help::ServerTp<PN::SV::AsyncService> {          \
 public:                                                                      \
  using miku::grpc_service_help::ServerTp<PN::SV::AsyncService>::ServerTp;    \
  enum RequestType {                                                          \
    M(SERVICE_HELP_GRPC_CORO_REQUEST_ENUM, CN, PN, SV)                        \
  };                                                                          \
  M(SERVICE_HELP_GRPC_CORO_FUN_DECLARE, CN, PN, SV)                           \
  void CreateOneRequest(int32_t type,                                         \
                        PN::SV::AsyncService *s,                              \
                        ::grpc::ServerCompletionQueue *cq_) override;         \
  void CreateAllRequest(PN::SV::AsyncService *s,                              \
                        ::grpc::ServerCompletionQueue *cq_) override;         \
};                                                                            \
}  // namespace miku::coro_service

#endif  // ifndef SERVICE_HELP_GRPC_CORO_SERVICE_DECLARE



#ifndef SERVICE_HELP_GRPC_CORO_SERVICE_IMPL
# define SERVICE_HELP_GRPC_CORO_SERVICE_IMPL(CN, PN, SV, M)                   \
namespace miku::coro_service {                                                \
M(SERVICE_HELP_GRPC_CORO_FUN_IMPL, CN, PN, SV)                                \
void CN##CoroServer::CreateOneRequest(int32_t type,                           \
                                      PN::SV::AsyncService *s,                \
                                      ::grpc::ServerCompletionQueue *cq_) {   \
  switch (type) {                                                             \
   M(SERVICE_HELP_GRPC_CORO_REQUEST_CREATE_ONE, CN, PN, SV)                   \
   default:                                                                   \
    LogWarn("unknow type. can not be run here!");                             \
  }                                                                           \
}                                                                             \
void CN##CoroServer::CreateAllRequest(                                        \
    PN::SV::AsyncService *s,                                                  \
    ::grpc::ServerCompletionQueue *cq_) {                                     \
  M(SERVICE_HELP_GRPC_CORO_REQUEST_CREATE_ALL, CN, PN, SV)                    \
}                                                                             \
                                                                              \
}  // namespace miku::coro_service

#endif  // ifndef SERVICE_HELP_GRPC_CORO_SERVICE_IMPL

//  协程服务端定义代码
//  =========================== end ========================
