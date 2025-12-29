#pragma once

#include <list>
#include <memory>
#include <atomic>
#include <iostream>

#include <time.h>

#include "lock_helper.h"

namespace miku {

template <typename T>
class Pool {
 private:
  struct PoolData {
    std::shared_ptr<T> ptr_;  // 指向数据的指针
    time_t ts_;               // 最近使用的时间
  };

  std::list<PoolData> pd_;  // 池中数据
  LockHelper l_;            // 获取和放回池中的锁
  uint32_t idle_;           // 空间时间，超过该时间则释放，单位s
  typename T::Conf conf_;   // 传递给T::Create函数的参数
  std::atomic_uint32_t c_;  // 记录，保底释放
  static const uint32_t auto_release = 10000;  // 放回次数达到该数值时，自动做次release兜底
  static const uint32_t max_try_get = 3;  // 最大尝试获取有效handler


 public:
  std::shared_ptr<T> Get() {        // 取资源
    return l_.serialization([&]() -> std::shared_ptr<T> {
      for (uint32_t i = 0; i < max_try_get; i++) {
        if (pd_.empty()) {
          auto ptr = std::shared_ptr<T>(T::Create(this->conf_));
          if (ptr->Alive()) {
            return ptr;
          }
        } else {
          auto rptr = pd_.front().ptr_;
          pd_.pop_front();
          if (rptr->Alive()) {
            return rptr;
          }
        }
      }

      return nullptr;
    });
  }

  void Put(std::shared_ptr<T> p) {  // 放回资源
    l_.serialization([&]() -> void {
      pd_.push_front({p, time(nullptr)});
    });

    if (++c_ % auto_release == 0) {  // 兜底机制
      Release();
    }
  }

  void Release() {                  // 释放空闲资源
    time_t expire = time(nullptr) - idle_;
    auto l = l_.WrLock();
    while (!pd_.empty()) {
      if (pd_.back().ts_ < expire) {
        pd_.pop_back();
      } else {
        break;
      }
    }
  }

  Pool(const typename T::Conf &conf, uint32_t idle = 300)
    : idle_(idle < 60 ? 60 : idle)
    , conf_(conf) {
  }
  Pool(uint32_t idle = 300)
    : idle_(idle < 60 ? 60 : idle) {
  }

  void SetConf(const typename T::Conf &conf) {
    conf_ = conf;
  }

  ~Pool() = default;
};

}  // namespace
