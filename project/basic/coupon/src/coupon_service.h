#pragma once

#include "proto/coupon.grpc.pb.h"

#include <string>

#include "middle/mysql_help.h"

struct CouponServiceConfig {
  std::string sign_key;
  std::string schema_bname;
  std::string table_bname;
  std::string record_bname;
};

class CouponServiceContext {
 public:
  constexpr static uint32_t schema_count = 8;
  constexpr static uint32_t table_count = 100;

  CouponServiceContext(const CouponServiceConfig &conf);
  ~CouponServiceContext() = default;

  std::string CouponTName(uint32_t idx) const;
  std::string RecordTName(uint32_t idx, uint64_t tnow) const;

  // 数据破坏做的作废动作
  int32_t CouponAbnormal(const std::string &coupon_no) const;
  // 检测到数据过期做自动过期处理
  int32_t CouponExpire(
      const std::string &coupon_no,
      const uint64_t operator_id = 1000,
      std::string *err_msg = nullptr,
      const std::vector<std::pair<std::string, std::string>> &attrs = {}) const;


  const CouponServiceConfig &conf_;
  miku::MysqlRouter<schema_count, table_count> mysql_router;
};


class CouponServiceImpl final : public miku::coupon::interface::Service {
 public:
  CouponServiceImpl(const CouponServiceContext &ctx);
  ~CouponServiceImpl() = default;
  grpc::Status Create(grpc::ServerContext* context,
                      const miku::coupon::CreateReq *request,
                      miku::coupon::CreateResp *reply) override;

  grpc::Status Invocation(grpc::ServerContext* context,
                          const miku::coupon::InvocationReq *request,
                          miku::coupon::InvocationResp *reply) override;

  grpc::Status Exchange(grpc::ServerContext* context,
                        const miku::coupon::ExchangeReq *request,
                        miku::coupon::ExchangeResp *reply) override;

  grpc::Status Cancel(grpc::ServerContext* context,
                      const miku::coupon::CancelReq *request,
                      miku::coupon::CancelResp *reply) override;

  grpc::Status Expire(grpc::ServerContext* context,
                      const miku::coupon::ExpireReq *request,
                      miku::coupon::ExpireResp *reply) override;

  grpc::Status Find(grpc::ServerContext* context,
                    const miku::coupon::FindReq *request,
                    miku::coupon::FindResp *reply) override;

  const CouponServiceContext &ctx_;
};


