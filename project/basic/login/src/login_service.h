#pragma once

#include "proto/login.grpc.pb.h"

#include <string>
#include <map>

#include "login.h"
#include "middle/mysql_help.h"
#include "middle/redis_help.h"


struct LoginServiceConfig {
  std::string sign_key;
  std::string schema_bname;
  std::string table_bname;
  std::string record_bname;
};

class LoginServiceContext {
 public:
  constexpr static uint32_t schema_count = 8;
  constexpr static uint32_t table_count = 100;

  LoginServiceContext(const LoginServiceConfig &conf);
  ~LoginServiceContext() = default;

  std::string LoginTName(uint32_t idx) const;
  std::optional<std::string>
  EncryptData(const std::string &r, const std::string &s) const;
  std::optional<std::string>
  DecryptData(const std::string &e, const std::string &s) const;
  std::string HashData(const std::string &r, const std::string &s) const;

  bool AddLoginAttr(Login *pl,
                    const std::string &k,
                    const std::string &v,
                    const int32_t &op) const;             // 0增加，其它减少
  std::vector<std::pair<std::string, std::string>>
  GetLoginAttr(const Login &l) const;

  // 数据破坏做的作废动作
  int32_t LoginAbnormal(const std::string &appid,
                        const std::string &auth_key) const;

  const LoginServiceConfig &conf_;
  miku::MysqlRouter<schema_count, table_count> mysql_router;
  std::shared_ptr<miku::RedisProxy> redis_proxy;
};


class LoginServiceImpl final : public miku::login::interface::Service {
 public:
  LoginServiceImpl(const LoginServiceContext &ctx);
  ~LoginServiceImpl() = default;
  grpc::Status Register(grpc::ServerContext* context,
                        const miku::login::RegisterReq *request,
                        miku::login::RegisterResp *reply) override;

  grpc::Status Login(grpc::ServerContext* context,
                     const miku::login::LoginReq *request,
                     miku::login::LoginResp *reply) override;

  grpc::Status Update(grpc::ServerContext* context,
                      const miku::login::UpdateReq *request,
                      miku::login::UpdateResp *reply) override;

  grpc::Status Freeze(grpc::ServerContext* context,
                      const miku::login::FreezeReq *request,
                      miku::login::FreezeResp *reply) override;

  grpc::Status Unfreeze(grpc::ServerContext* context,
                        const miku::login::UnfreezeReq *request,
                        miku::login::UnfreezeResp *reply) override;

  grpc::Status Cancel(grpc::ServerContext* context,
                      const miku::login::CancelReq *request,
                      miku::login::CancelResp *reply) override;

  grpc::Status Find(grpc::ServerContext* context,
                    const miku::login::FindReq *request,
                    miku::login::FindResp *reply) override;

  const LoginServiceContext &ctx_;
};


