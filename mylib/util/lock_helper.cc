#include "util/lock_helper.h"


namespace miku {

std::unique_lock<std::shared_mutex> LockHelper::Lock() const {
  return std::unique_lock(mutex_);
}

std::shared_lock<std::shared_mutex> LockHelper::RdLock() const {
  return std::shared_lock(mutex_);
}

std::unique_lock<std::shared_mutex> LockHelper::WrLock() const {
  return Lock();
}

}  // namespace miku
