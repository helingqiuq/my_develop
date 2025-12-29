#pragma once

#include <string>

#include "util/task_help.h"
#include "util/time_cost.h"
#include "util/protobuf_convert.h"
#include "util/log.h"


namespace miku {
template <typename REQ, typename RESP>
auto auto_log_rpc(const char *name, const REQ &req, const RESP &resp) {
  static auto log_proc = [](
      std::shared_ptr<miku::TimeCost> &time_cost,
      const char *name,
      const REQ &req,
      const RESP &resp) {
    std::string sreq, sresp;
    miku::protobuf_to_json(req, &sreq);
    miku::protobuf_to_json(resp, &sresp);
    LogInfo("<cost " << time_cost->TotalCost() << "ms> "
            << name
            << " req: " << sreq
            << " resp: " << sresp);

  };

  return miku::make_ending_task(
      log_proc, std::make_shared<miku::TimeCost>(), name, req, resp);
}

template <typename REQ, typename RESP>
auto auto_log_http(const char *name, const REQ &req, const RESP &resp) {
  static auto log_proc = [](
      std::shared_ptr<miku::TimeCost> &time_cost,
      const char *name,
      const REQ &req,
      const RESP &resp) {
    std::string sreq, sresp;
    miku::protobuf_to_json(req, &sreq, true);
    miku::protobuf_to_json(resp, &sresp, true);
    LogInfo("<cost " << time_cost->TotalCost() << "ms> "
            << name
            << " req: " << sreq
            << " resp: " << sresp);

  };

  return miku::make_ending_task(
      log_proc, std::make_shared<miku::TimeCost>(), name, req, resp);
}

}  // namespace miku

#define AUTO_LOG_RPC(req, rsp) \
  miku::auto_log_rpc(__PRETTY_FUNCTION__, req, rsp)
#define AUTO_LOG_HTTP(req, rsp) \
  miku::auto_log_http(__PRETTY_FUNCTION__, req, rsp)
