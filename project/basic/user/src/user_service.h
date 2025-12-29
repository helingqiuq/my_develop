#pragma once

#include "proto/user.grpc.pb.h"

#include <string>
#include <map>

#include "user.h"
#include "middle/mysql_help.h"
#include "middle/redis_help.h"


struct UserServiceConfig {
  std::string sign_key;
  std::string schema_bname;
  std::string table_bname;
  std::string record_bname;

  std::string user_id_genkey;
};

class UserServiceContext {
 public:
  constexpr static uint32_t schema_count = 8;
  constexpr static uint32_t table_count = 100;

  UserServiceContext(const UserServiceConfig &conf);
  ~UserServiceContext() = default;

  std::string UserTName(uint32_t idx) const;
  std::string RecordTName(uint32_t idx, uint64_t tnow) const;
  std::optional<std::string>
  EncryptData(const std::string &r, const std::string &s) const;
  std::optional<std::string>
  DecryptData(const std::string &e, const std::string &s) const;
  bool AddUserAttr(User *pu,
                   const std::string &k,
                   const std::string &v,
                   const int32_t &op,             // 0增加，其它减少
                   Json::Value *jr) const;        // 需要更新的record.attr
  std::vector<std::pair<std::string, std::string>>
  GetUserAttr(const User &u) const;
  std::optional<uint64_t> GenUserId(uint32_t uid_type = 0) const;  // 考虑后面集群账户

  // 数据破坏做的作废动作
  int32_t UserAbnormal(const uint64_t &user_id) const;

  const UserServiceConfig &conf_;
  miku::MysqlRouter<schema_count, table_count> mysql_router;
  std::shared_ptr<miku::RedisProxy> redis_proxy;
};


class UserServiceImpl final : public miku::user::interface::Service {
 public:
  UserServiceImpl(const UserServiceContext &ctx);
  ~UserServiceImpl() = default;
  grpc::Status Create(grpc::ServerContext* context,
                      const miku::user::CreateReq *request,
                      miku::user::CreateResp *reply) override;

  grpc::Status Update(grpc::ServerContext* context,
                      const miku::user::UpdateReq *request,
                      miku::user::UpdateResp *reply) override;

  grpc::Status Freeze(grpc::ServerContext* context,
                      const miku::user::FreezeReq *request,
                      miku::user::FreezeResp *reply) override;

  grpc::Status Unfreeze(grpc::ServerContext* context,
                        const miku::user::UnfreezeReq *request,
                        miku::user::UnfreezeResp *reply) override;

  grpc::Status Cancel(grpc::ServerContext* context,
                      const miku::user::CancelReq *request,
                      miku::user::CancelResp *reply) override;

  grpc::Status Find(grpc::ServerContext* context,
                    const miku::user::FindReq *request,
                    miku::user::FindResp *reply) override;

  const UserServiceContext &ctx_;
};


