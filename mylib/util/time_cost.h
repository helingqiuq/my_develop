#pragma once

#include <time.h>
#include <stdint.h>

namespace miku {

class TimeCost {
 public:
  TimeCost();
  ~TimeCost();
  uint64_t Cost();
  uint64_t TotalCost();
 private:
  struct timespec tb_;  // 开始时间
  struct timespec tc_;  // 上一次获取耗时的时间
};

}  // namespace miku
