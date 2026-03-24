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
  uint64_t CostUs();
  uint64_t TotalCostUs();
  uint64_t CostNs();
  uint64_t TotalCostNs();
 private:
  struct timespec tb_;  // 开始时间
  struct timespec tc_;  // 上一次获取耗时的时间
};

}  // namespace miku
