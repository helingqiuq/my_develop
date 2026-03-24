#include "grpc_service_help.h"

namespace miku::grpc_service_help {

CoroCallContextBase::CoroCallContextBase(
      int32_t type,
      CoroTraits::promise_type *promise,
      CoroCallContextBase::CallStatus status)
    : type_(type)
    , promise_(promise)
    , status_(status) {
}

ServerBase::ServerBase(const miku::ServiceConfig &conf,
                       void *context,
                       uint32_t io_thread_cnt,
                       uint32_t work_thread_cnt)
      : conf_(conf)
      , context_(context)
      , io_thread_cnt_(io_thread_cnt)
      , coro_task_help_(work_thread_cnt)
      , exit_(false) {
}

ServerBase::~ServerBase() {
}


void
ServerBase::Shutdown() {
  server_->Shutdown();
  for (auto &cq : cq_) {
    cq->Shutdown();
  }
  exit_ = true;
}

void
ServerBase::Wait() {
  for (auto &t : tworks_) {
    if (t.native_handle()) {
      t.join();
    }
  }
}


}  // namespace miku::grpc_service_help

