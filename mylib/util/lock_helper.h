#pragma once
#include <memory>
#include <shared_mutex>
#include <mutex>

namespace miku {
class LockHelper {
 private:
  mutable std::shared_mutex mutex_;

 public:
  std::unique_lock<std::shared_mutex> Lock() const;
  std::shared_lock<std::shared_mutex> RdLock() const;
  std::unique_lock<std::shared_mutex> WrLock() const;

  template <typename F, typename ...Args>
  auto serialization(F f, Args && ... args) const {
    auto l = this->Lock();
    return f(std::forward<Args>(args)...);
  }

  template <typename F, typename ...Args>
  auto rdserialization(F f, Args && ... args) const {
    auto l = this->RdLock();
    return f(std::forward<Args>(args)...);
  }

  template <typename F, typename R, typename ...Args>
  bool try_lock_do(F f, R *r, Args && ... args) const {
    if (mutex_.try_lock()) {
      if (r != nullptr) {
        *r = f(std::forward<Args>(args)...);
      } else {
        f(std::forward<Args>(args)...);
      }
      mutex_.unlock();
      return true;
    } else {
      return false;
    }
  }
};

} // namespace miku
