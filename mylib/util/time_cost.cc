#include "util/time_cost.h"

namespace miku {

static uint64_t
time_cost_getcost(const struct timespec &tb,
                  const struct timespec &te) {
  uint64_t cost = 0;
  uint64_t sec = 0;
  if (te.tv_nsec < tb.tv_nsec) {
    cost = 1000000000 + te.tv_nsec - tb.tv_nsec;
    sec = te.tv_sec - 1;
  } else {
    cost = te.tv_nsec - tb.tv_nsec;
    sec = te.tv_sec;
  }

  cost /= 1000000;  // 毫秒单位
  cost += (sec - tb.tv_sec) * 1000;

  return cost;
}

TimeCost::TimeCost() {
  clock_gettime(CLOCK_REALTIME, &tb_);
  tc_.tv_sec = tb_.tv_sec;
  tc_.tv_nsec = tb_.tv_nsec;
}

TimeCost::~TimeCost() {
}

uint64_t TimeCost::Cost() {
  struct timespec tn;
  clock_gettime(CLOCK_REALTIME, &tn);
  uint64_t cost = time_cost_getcost(tc_, tn);
  tc_.tv_sec = tn.tv_sec;
  tc_.tv_nsec = tn.tv_nsec;
  return cost;
}

uint64_t TimeCost::TotalCost() {
  struct timespec tn;
  clock_gettime(CLOCK_REALTIME, &tn);
  uint64_t cost = time_cost_getcost(tb_, tn);
  tc_.tv_sec = tn.tv_sec;
  tc_.tv_nsec = tn.tv_nsec;
  return cost;
}

}  // namespace miku
