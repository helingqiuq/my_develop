#include "coro_task.h"


namespace miku::coro_task {

CoroRet
CoroRet::MakeNone() {
  return CoroRetNone;
}
CoroRet
CoroRet::MakeInt32(int32_t v) {
  return {INT32, {.i32 = v}};
}
CoroRet
CoroRet::MakeInt64(int64_t v) {
  return {INT64, {.i64 = v}};
}
CoroRet
CoroRet::MakeUInt32(uint32_t v) {
  return {UINT32, {.u32 = v}};
}
CoroRet
CoroRet::MakeUInt64(uint64_t v) {
  return {UINT64, {.u64 = v}};
}
CoroRet
CoroRet::MakeBool(bool v) {
  return {BOOL, {.b = v}};
}
CoroRet
CoroRet::MakePtr(void *v) {
  return {PTR, {.ptr = v}};
}

std::optional<int32_t>
CoroRet::GetInt32() const {
  if (type != INT32) {
    return std::nullopt;
  }
  return d.i32;
}
std::optional<uint32_t>
CoroRet::GetUInt32() const {
  if (type != UINT32) {
    return std::nullopt;
  }
  return d.u32;
}
std::optional<int64_t>
CoroRet::GetInt64() const {
  if (type != INT64) {
    return std::nullopt;
  }
  return d.i64;
}
std::optional<uint64_t>
CoroRet::GetUInt64() const {
  if (type != UINT64) {
    return std::nullopt;
  }
  return d.u64;
}
std::optional<bool>
CoroRet::GetBool() const {
  if (type != BOOL) {
    return std::nullopt;
  }
  return d.b;
}
std::optional<void
*> CoroRet::GetPtr() const {
  if (type != PTR) {
    return std::nullopt;
  }
  return d.ptr;
}

CoroRet::operator bool() const {
  switch (type) {
   case NONE:
    return false;
   case INT32:
    return d.i32 != 0;
   case UINT32:
    return d.u32 != 0;
   case INT64:
    return d.i64 != 0;
   case UINT64:
    return d.u64 != 0;
   case BOOL:
    return d.b;
   case PTR:
    return d.ptr != nullptr;
  }
  return false;
}

void
CoroTaskHelp::work_thread_proc(CoroTaskHelp *t) {
  while (!t->exit_) {
#if 1
    std::queue<void *> tasks;
    t->lock_.serialization([&]() -> void {
        tasks.swap(t->tasks_);
    });

    if (tasks.empty()) {
      std::unique_lock<std::mutex> lock(t->mu_);
      t->cv_.wait(lock);
      if (t->exit_) {
        break;
      }
      continue;
    }

    while (!tasks.empty()) {
      auto *addr = tasks.front();
      tasks.pop();
      auto h = std::coroutine_handle<Traits::promise_type>::from_address(addr);
      h.resume();
    }
#endif
#if 0
    void *handler_address;
    t->lock_.serialization([&]() -> void {
      if (!t->tasks_.empty()) {
        handler_address = t->tasks_.front();
        t->tasks_.pop();
      } else {
        handler_address = nullptr;
      }
    });

    if (handler_address == nullptr) {
      std::unique_lock<std::mutex> lock(t->mu_);
      t->cv_.wait(lock);
      if (t->exit_) {
        break;
      }
      continue;
    }

    auto h = std::coroutine_handle<Traits::promise_type>::from_address(
        handler_address);
    h.resume();
#endif
  }
}

CoroTaskHelp::CoroTaskHelp(uint32_t work_thread_cnt)
      : work_thread_cnt_(work_thread_cnt)
      , exit_(false) {
  work_threads_.resize(work_thread_cnt_);
  for (uint32_t i = 0; i < work_thread_cnt_; i++) {
    std::thread t(work_thread_proc, this);
    work_threads_[i].swap(t);
  }
}

CoroTaskHelp::~CoroTaskHelp() {
  Shutdown();
}

void
CoroTaskHelp::Shutdown() {
  exit_ = true;
  cv_.notify_all();
  for (auto &t : work_threads_) {
    if (t.native_handle()) {
      t.join();
    }
  }
}

CoroTaskHelp::CoAwait
CoroTaskHelp::DoParallel(CoroTaskHelp::Parallel &parallel) {
  for (auto *handler_address : parallel.handler_address_) {
    auto h = std::coroutine_handle<Traits::promise_type>::from_address(
        handler_address);
    h.promise().coro_task_help_ = this;
  }
  return {this, std::move(parallel.handler_address_)};
}

CoroTaskHelp::CoAwait::CoAwait(
      CoroTaskHelp *th,
      std::vector<void *> sub_tasks)
    : th_(th)
    , sub_tasks_(std::move(sub_tasks)) {
}

bool
CoroTaskHelp::CoAwait::await_ready() const {
  return false;
}

CoroRet
CoroTaskHelp::CoAwait::await_resume() {
  return ret_;
}

void
CoroTaskHelp::CoAwait::await_suspend(std::coroutine_handle<> handle) {
  auto *promise = reinterpret_cast<CoroTaskHelp::Traits::promise_type *>(
                                                          handle.address());
  promise->parallel_cnt_ = sub_tasks_.size();
  promise_ = promise;

  if (sub_tasks_.size() > 0) {
    for (const auto &sub_task_: sub_tasks_) {
      auto &sub_promise = std::coroutine_handle<
            Traits::promise_type>::from_address(sub_task_).promise();
      sub_promise.parent_ = promise;
      sub_promise.ret_ = &ret_;  // 多个sub时，随便保存一个吧
      if (th_ != nullptr) {
        th_->lock_.serialization([&]() -> void {
          th_->tasks_.push(sub_task_);
        });
        th_->cv_.notify_one();
      }
    }
  }
}

CoroTaskHelp::Traits
CoroTaskHelp::Traits::promise_type::get_return_object() {
  return {std::coroutine_handle<
        CoroTaskHelp::Traits::promise_type>::from_promise(*this)};
}

std::suspend_always
CoroTaskHelp::Traits::promise_type::initial_suspend() noexcept {
  return {};
}

std::suspend_never
CoroTaskHelp::Traits::promise_type::final_suspend() noexcept {
  if (parent_ != nullptr) {
    if (--parent_->parallel_cnt_ == 0) {
      auto h = std::coroutine_handle<promise_type>::from_address(parent_);
      h.resume();
    }
  }
  return {};
}

void
CoroTaskHelp::Traits::promise_type::unhandled_exception() {
  std::terminate();
}

#if 0
void
CoroTaskHelp::Traits::promise_type::return_void() {
}
#endif

#if 1
void
CoroTaskHelp::Traits::promise_type::return_value(CoroRet ret) {
  if (ret_ != nullptr) {
    *ret_ = ret;
  }
}
#endif

std::suspend_never
CoroTaskHelp::Traits::promise_type::yield_value(promise_type **p) {
  *p = this;
  return {};
}

std::suspend_never
CoroTaskHelp::Traits::promise_type::yield_value(CoroTaskHelp **coro_task_help) {
  *coro_task_help = coro_task_help_;
  return {};
}

std::suspend_never
CoroTaskHelp::Traits::promise_type::yield_value(void *user_data) {
  user_data_ = user_data;
  return {};
}



}  // namespace miku::coro_task
