#pragma once

#include <coroutine>
#include <thread>
#include <iostream>
#include <string>
#include <chrono>
#include <queue>
#include <vector>
#include <mutex>
#include <atomic>
#include <functional>
#include <condition_variable>
#include <type_traits>
#include <optional>

#include <stdint.h>

#include "lock_helper.h"


namespace miku::coro_task {

struct CoroRet {
  enum CoroRetType {
    NONE    =  0,     // 无返回
    INT32   =  1,     // 返回int32_值
    UINT32  =  2,     // 返回uint32_t值
    INT64   =  3,     // 返回int64_t值
    UINT64  =  4,     // 返回uint64_t值
    BOOL    =  5,     // 返回bool值
    PTR     =  6,     // 返回void *值
  } type;

  union {
    int32_t i32;
    uint32_t u32;
    int64_t i64;
    uint64_t u64;
    bool b;
    void *ptr;
  } d;

  static CoroRet MakeNone();
  static CoroRet MakeInt32(int32_t v);
  static CoroRet MakeInt64(int64_t v);
  static CoroRet MakeUInt32(uint32_t v);
  static CoroRet MakeUInt64(uint64_t v);
  static CoroRet MakeBool(bool v);
  static CoroRet MakePtr(void *d);

  std::optional<int32_t> GetInt32() const;
  std::optional<uint32_t> GetUInt32() const;
  std::optional<int64_t> GetInt64() const;
  std::optional<uint64_t> GetUInt64() const;
  std::optional<bool> GetBool() const;
  std::optional<void *> GetPtr() const;

  inline int32_t QueryInt32() const { return d.i32; }
  inline uint32_t QueryUInt32() const { return d.u32; }
  inline int64_t QueryInt64() const { return d.i64; }
  inline uint64_t QueryUInt64() const { return d.u64; }
  inline bool QueryBool() const { return d.b; }
  inline void *QueryPtr() const { return d.ptr; }

  explicit operator bool() const;
};

static constexpr CoroRet CoroRetNone = {CoroRet::CoroRetType::NONE,
                                        {.ptr = nullptr}};
static constexpr CoroRet CoroRetTrue = {CoroRet::CoroRetType::BOOL,
                                        {.b = true}};
static constexpr CoroRet CoroRetFalse = {CoroRet::CoroRetType::BOOL,
                                         {.b = false}};

struct CoroTaskHelp final {
  struct Traits {
    struct promise_type {
      Traits get_return_object();
      std::suspend_always initial_suspend() noexcept;
      std::suspend_never final_suspend() noexcept;
      void unhandled_exception();
      //void return_void();  // 如果有返回值，需要写其它函数，对应co_retrun
      void return_value(CoroRet ret_);  // 如果有返回值，需要写其它函数，对应co_retrun
      std::suspend_never yield_value(promise_type **promise);
      std::suspend_never yield_value(CoroTaskHelp **coro_task_help);
      std::suspend_never yield_value(void *user_data);

      promise_type *parent_ = nullptr;
      std::atomic<uint32_t> parallel_cnt_ = 0;
      CoroTaskHelp *coro_task_help_ = nullptr;  // 并行执行时需要设置该变量
      void *user_data_ = nullptr;  // 自定义数据
      CoroRet *ret_ = nullptr;
    };

    std::coroutine_handle<Traits::promise_type> h_;
  };

  struct CoAwait {
    CoAwait(CoroTaskHelp *th = nullptr,
            std::vector<void *> sub_tasks = {});
    bool await_ready() const;
    CoroRet await_resume();  // 如果co_await有返回值，这个函数有返回值
    void await_suspend(std::coroutine_handle<> handle);

    CoroTaskHelp *th_;
    std::vector<void *> sub_tasks_;
    Traits::promise_type *promise_;
    CoroRet ret_;
  };

  struct Parallel {
    template <typename PROC, typename ... ARGS>
    void AddTask(const PROC &proc, ARGS && ... args) {
      if constexpr (std::is_same_v<decltype(proc(std::forward<ARGS>(args) ...)), Traits>) {
        auto do_proc = [](auto proc) -> Traits {
          CoroTaskHelp *pcth;
          auto h = proc();
          if (h.h_) {
            co_yield &pcth;
            co_await CoAwait(pcth, {h.h_.address()});
          }
        };

        auto h = do_proc(std::bind(proc, std::forward<ARGS>(args) ...));
        handler_address_.push_back(h.h_.address());
      } else {
        auto do_proc = [](auto proc)-> Traits {
          co_yield reinterpret_cast<void *>(0);
          proc();
        };

        auto h = do_proc(std::bind(proc, std::forward<ARGS>(args) ...));
        handler_address_.emplace_back(h.h_.address());
      }
    }

    std::vector<void *> handler_address_;
  };

  CoAwait DoParallel(Parallel &parallel);

  static void work_thread_proc(CoroTaskHelp *t);
  explicit CoroTaskHelp(uint32_t work_thread_cnt = 1);
  ~CoroTaskHelp();
  void Shutdown();


  template <typename PROC, typename ... ARGS>
  CoAwait DoTask(const PROC &proc, ARGS && ... args) {
    if constexpr (std::is_same_v<
          decltype(proc(std::forward<ARGS>(args) ...)), Traits>) {
      auto do_proc = [](CoroTaskHelp *coro_help,
                        auto proc)-> Traits {
        auto h = proc();
        if (h.h_) {
          co_return co_await CoAwait(coro_help, {h.h_.address()});
        }
      };

      auto h = do_proc(this, std::bind(proc, std::forward<ARGS>(args) ...));
      return {this, {h.h_.address()}};
    } else {
      auto do_proc = [](auto proc)-> Traits {
        co_yield reinterpret_cast<void *>(0);
        proc();
      };

      auto h = do_proc(std::bind(proc, std::forward<ARGS>(args) ... ));
      return {this, {h.h_.address()}};
    }
  }

  std::vector<std::thread> work_threads_;
  std::queue<void *> tasks_;
  std::mutex mu_;
  std::condition_variable cv_;
  uint32_t work_thread_cnt_;
  bool exit_;
  miku::LockHelper lock_;
};

}  //namespace miku::coro_task
