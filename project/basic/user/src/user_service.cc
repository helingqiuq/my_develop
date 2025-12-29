#include "user_service.h"
#include "user.h"
#include "user_record.h"

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <optional>

#include "proto/user.grpc.pb.h"
#include "middle/redis_help.h"
#include "middle/mysql_help.h"
#include "middle/app_help.h"
#include "middle/auto_rpc_log.h"
#include "util/util.h"
#include "curl/curl.h"
#include "json/json.h"
#include "util/log.h"
#include "encrypt_help/encrypt.h"


#define SET_REPLAY(eno, emsg) do {      \
  reply->set_ret(eno);                  \
  reply->set_msg(emsg);                 \
} while (0)


UserServiceContext::UserServiceContext(const UserServiceConfig &conf)
    : conf_(conf) {
}

std::string
UserServiceContext::UserTName(uint32_t idx) const {
  return conf_.table_bname + "_" +  std::to_string(idx);
}

std::string
UserServiceContext::RecordTName(uint32_t idx, uint64_t tnow) const {
  return conf_.record_bname +
          "_" + std::to_string(idx) +
          "_" + miku::ts_to_year(tnow);
}

int32_t
UserServiceContext::UserAbnormal(const uint64_t &user_id) const {
  time_t tnow = time(nullptr);
  auto [dbproxy, sindex, tindex] = mysql_router.GetProxy(user_id);
  std::string dtname = UserTName(tindex);
  std::string rtname = RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_user;
  std::string sql_record;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = User::SelectOne(h, dtname, 0, user_id, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::user::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::user::ErrNo::E_NOEXISTS;
        }

        auto &u = *d;
        UserRecord record;
        record.user_id = u.user_id;
        record.type = miku::user::UserOpType::UOP_ABNORMAL;
        record.attr = Json::objectValue;
        record.operator_id = 1000;  // 只能系统检测到设置
        record.created = tnow;
        record.context = "";
        record.extension = Json::objectValue;
        record.Sign(conf_.sign_key);

        sql_user = u.MakeAbnormalSql(dtname);
        sql_record = record.MakeInsertSql(rtname);

        return 0;
      },
      sql_user,
      sql_record);

  return ret;
}
std::optional<std::string>
UserServiceContext::EncryptData(const std::string &r,
                                const std::string &s) const {
  if (r.empty()) {
    LogInfo("EncryptData is empty");
    return std::nullopt;
  }

  ResultBuffer *rb;
  int32_t ret = miku_b64_sm4_cbc_encrypt_arb(
      reinterpret_cast<const uint8_t *>(r.c_str()),
      r.length(),
      reinterpret_cast<const uint8_t *>(conf_.sign_key.c_str()),
      conf_.sign_key.length(),
      reinterpret_cast<const uint8_t *>(s.c_str()),
      s.length(),
      &rb);
  if (ret <= 0) {
    LogWarn("EncryptData failed");
    return std::nullopt;
  }

  std::string rs(reinterpret_cast<const char *>(rb->d), rb->n);
  encrypt_help_result_destroy(rb);
  return rs;
}

std::optional<std::string>
UserServiceContext::DecryptData(const std::string &e,
                                const std::string &s) const {
  if (e.empty()) {
    LogInfo("DecryptData is empty");
    return std::nullopt;
  }

  ResultBuffer *rb;
  int32_t ret = miku_b64_sm4_cbc_decrypt_arb(
      reinterpret_cast<const uint8_t *>(e.c_str()),
      e.length(),
      reinterpret_cast<const uint8_t *>(conf_.sign_key.c_str()),
      conf_.sign_key.length(),
      reinterpret_cast<const uint8_t *>(s.c_str()),
      s.length(),
      &rb);
  if (ret <= 0) {
    LogWarn("DecryptData failed");
    return std::nullopt;
  }

  std::string rs(reinterpret_cast<const char *>(rb->d), rb->n);
  encrypt_help_result_destroy(rb);
  return rs;
}

bool
UserServiceContext::AddUserAttr(
    User *pu,
    const std::string &k,
    const std::string &v,
    const int32_t &op,
    Json::Value *pjr) const {
  assert(pu != nullptr && pjr != nullptr);

  auto &jr = *pjr;  // jr一定没有被设置过
  const auto &u = *pu;  // 这里不改值
  const auto *pkconf = UserAttrKeyConfig::get_key_config(k);
  if (pkconf == nullptr) {
    return false;
  }
  Json::Value *pju = nullptr;
  if (pkconf->belong_to == UserAttrKeyConfig::BELONG_TO::ATTR) {
    pju = &pu->attr;
  } else if (pkconf->belong_to == UserAttrKeyConfig::BELONG_TO::PARAM) {
    pju = &pu->param;
  } else {
    LogWarn("unknow set where.");
    return false;
  }
  auto &ju = *pju;

  const std::string *pd = nullptr;
  std::optional<std::string> oev = std::nullopt;
  if (pkconf->encrypt) {
    oev = EncryptData(v, u.salt);
    if (!oev) {
      LogWarn("EncryptData failed.");
      return false;
    }
    pd = &(*oev);
  } else {
    pd = &v;
  }
  const auto &d = *pd;

  bool update = false;
  jr[k].append(d);
  jr[k + "_op"].append(op);
  if (pkconf->multiple) {
    if (ju.isMember(k.c_str()) && !ju[k].isArray()) {  // 类型判断，只会做删除
      jr[k + "_del_raw"] = std::move(ju[k]);  // 流水记录删除的数据
      ju.removeMember(k.c_str());
      update = true;  // 这里有做数据更新
    }

    bool has = miku::json_sarr_has_value(ju[k], d);
    if (op == 0) {  // 增加
      if (has) {
        return false;
      }
      ju[k].append(d);
      return true;
    } else {  // 减少
      if (!has) {
        return update;
      }

      miku::json_sarr_remove_value(&ju[k], d);
      if (ju[k].isArray() && ju[k].size() == 0) {  // 删掉
        ju.removeMember(k.c_str());
      }
      return true;
    }
  } else {
    bool has = false;
    if (ju.isMember(k.c_str())) {  // 类型判断，只会做删除
      if (!ju[k].isString()) {
        jr[k + "_del_raw"] = std::move(ju[k]);  // 流水记录删除的数据
        ju.removeMember(k.c_str());
        update = true;
      } else {
        has = (ju[k] == d);
      }
    }

    if (op == 0) {  // 增加
      if (has) {  // 已存在
        return false;
      }
      ju[k] = d;
      return true;
    } else {  // 减少
      if (!has) {
        return update;
      }
      ju.removeMember(k.c_str());
      return true;
    }
  }
}

std::vector<std::pair<std::string, std::string>>
UserServiceContext::GetUserAttr(const User &u) const {
  std::vector<std::pair<std::string, std::string>> vr;
  static auto set_attr = [](
      const UserServiceContext *pctx,
      std::vector<std::pair<std::string, std::string>> *pvr,
      const Json::Value &jv,
      const std::string &salt) -> void {
    for (auto it = jv.begin(); it != jv.end(); ++it) {
      const std::string &k = it.name();
      const auto *pkconf = UserAttrKeyConfig::get_key_config(k);
      if (pkconf == nullptr) {
        continue;
      }
      if (pkconf->multiple) {
        if (it->isArray()) {
          for (const auto &v : *it) {
            if (v.isString()) {
              if (pkconf->encrypt) {
                auto orv = pctx->DecryptData(v.asString(), salt);
                if (!orv) {
                  LogWarn("DecryptData failed");
                } else {
                  pvr->emplace_back(k, *orv);
                }
              } else {
                pvr->emplace_back(k, v.asString());
              }
            }
          }
        }
      } else if (it->isString()) {
        if (pkconf->encrypt) {
          auto orv = pctx->DecryptData(it->asString(), salt);
          if (!orv) {
            LogWarn("DecryptData failed");
          } else {
            pvr->emplace_back(k, *orv);
          }
        } else {
          pvr->emplace_back(k, it->asString());
        }
      }
    }
  };
  set_attr(this, &vr, u.attr, u.salt);
  set_attr(this, &vr, u.param, u.salt);

  return vr;
}

std::optional<uint64_t>
UserServiceContext::GenUserId(uint32_t /*uid_type*/) const {
  auto rh = redis_proxy->Command("incr %s", conf_.user_id_genkey.c_str());
  auto *rp = rh->Reply();
  if (rp->type != REDIS_REPLY_INTEGER && rp->type != REDIS_REPLY_BIGNUM) {
    LogWarn("GenUid incr not get number");
    return std::nullopt;
  }

  return rp->integer;
}


UserServiceImpl::UserServiceImpl(const UserServiceContext &ctx)
    : ctx_(ctx) {
}


grpc::Status
UserServiceImpl::Create(grpc::ServerContext *context,
                          const miku::user::CreateReq *request,
                          miku::user::CreateResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::user::CreateReq &req,
                              std::string *err_msg) -> bool {
    if (req.user_id() == 0 && !req.gen_user_id()) {
      *err_msg = "user_id not set.";
      return false;
    }

    if (req.user_type() == miku::user::UserType::UT_COMMON) {
      // nothing
    } else /* if (req.user_type() == ??) {} */ {
      *err_msg = "know user type.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::user::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  // user创建
  User u;

  //u.id = 0;  // 不设置
  if (request->user_id() != 0) {  // 这里通过参数校验
    u.user_id = request->user_id();
  } else {
    auto ou = ctx_.GenUserId();
    if (!ou) {
      SET_REPLAY(miku::user::ErrNo::E_ERROR, "内部错误");
      return grpc::Status::OK;
    }
    u.user_id = *ou;
  }
  u.salt = miku::make_random_string();
  u.src_id = request->src_id();
  u.type = request->user_type();
  u.status = miku::user::UserStatus::US_COMMON;
  u.param = Json::objectValue;
  u.attr = Json::objectValue;
  u.created = tnow;
  u.updated = tnow;
  u.context = "";
  u.extension = Json::objectValue;
  // u.signature
  //
  UserRecord record;
  for (const auto &p : request->attrs()) {
    ctx_.AddUserAttr(&u, p.k(), p.v(), p.op(), &record.attr);
  }

  // record创建
  record.user_id = u.user_id;
  record.type = miku::user::UserOpType::UOP_CREATE;
  //record.attr = u.attr;
  record.operator_id = request->operator_id();
  record.created = tnow;
  record.context = "";
  record.extension = Json::objectValue;
  // record.signature

  u.Sign(ctx_.conf_.sign_key);
  record.Sign(ctx_.conf_.sign_key);


  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(u.user_id);

  std::string dtname = ctx_.UserTName(tindex);
  std::string sql_user = u.MakeInsertSql(dtname);
  LogDebug("sql_user: " << sql_user);

  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string sql_record = record.MakeInsertSql(rtname);
  LogDebug("sql_record: " << sql_record);
  auto ret = dbproxy->Transaction({sql_user, sql_record});
  if (ret == ER_DUP_ENTRY) {  // 重复
    LogInfo("already exists.");
    SET_REPLAY(miku::user::ErrNo::E_EXISTS, "id已被占用.");
    return grpc::Status::OK;
  }

  if (ret != 0) {
    LogWarn("exec sql failed. sql:[" << sql_user << "]["
                                     << sql_record << "]");
    SET_REPLAY(miku::user::ErrNo::E_STATUS, "exec sql failed.");
    return grpc::Status::OK;
  }

  reply->set_user_id(u.user_id);
  SET_REPLAY(miku::user::ErrNo::E_SUCCESS, "");
  return grpc::Status::OK;
}

grpc::Status
UserServiceImpl::Update(grpc::ServerContext *context,
                        const miku::user::UpdateReq *request,
                        miku::user::UpdateResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::user::UpdateReq &req,
                              std::string *err_msg) -> bool {
    if (req.user_id() == 0) {
      *err_msg = "user_no not set.";
      return false;
    }

    if (req.operator_id() == 0) {
      *err_msg = "operator_id not set.";
      return false;
    }

    if (req.attrs_size() == 0) {
      *err_msg = "attrs not set.";
      return false;
    }

    for (const auto &p : req.attrs()) {
      const auto &k = p.k();
      if (!UserAttrKeyConfig::is_valid_key(k)) {
        *err_msg = "key " + k + " can not set.";
        return false;
      }
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::user::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }


  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &user_id = request->user_id();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(user_id);
  std::string dtname = ctx_.UserTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_user;
  std::string sql_record;
  bool abnormal_user = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = User::SelectOne(h, dtname, 0, user_id, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::user::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::user::ErrNo::E_NOEXISTS;
        }

        auto &u = *d;
        if (u.status == miku::user::UserStatus::US_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal user.");
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (!u.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_user = true;
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (u.status != miku::user::UserStatus::US_COMMON) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::user::ErrNo::E_STATUS;
        }

        bool uupdate = false;
        UserRecord record;
        for (const auto &p : request->attrs()) {
          uupdate = ctx_.AddUserAttr(&u, p.k(), p.v(), p.op(), &record.attr);
        }

        record.user_id = u.user_id;
        record.type = miku::user::UserOpType::UOP_UPDATE;
        //record.attr = json::objectValue;
        record.operator_id = request->operator_id();
        record.created = tnow;
        record.context = "";
        record.extension = Json::objectValue;
        record.Sign(ctx_.conf_.sign_key);

        u.updated = tnow;
        u.Sign(ctx_.conf_.sign_key);

        if (uupdate) {
          sql_user = u.MakeUpdateSql(dtname);
          sql_record = record.MakeInsertSql(rtname);
        } else {
          sql_user = "";
          sql_record = "";
        }

        return 0;
      },
      sql_user,
      sql_record);

  if (abnormal_user) {
    ctx_.UserAbnormal(user_id);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::user::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}

grpc::Status
UserServiceImpl::Freeze(grpc::ServerContext *context,
                        const miku::user::FreezeReq *request,
                        miku::user::FreezeResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::user::FreezeReq &req,
                              std::string *err_msg) -> bool {
    if (req.user_id() == 0) {
      *err_msg = "user_no not set.";
      return false;
    }

    if (req.operator_id() == 0) {
      *err_msg = "operator_id not set.";
      return false;
    }
    // 有些参数的检查需要等查到票的类型才可确定

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::user::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &user_id = request->user_id();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(user_id);
  std::string dtname = ctx_.UserTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_user;
  std::string sql_record;
  bool abnormal_user = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = User::SelectOne(h, dtname, 0, user_id, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::user::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::user::ErrNo::E_NOEXISTS;
        }

        auto &u = *d;
        if (u.status == miku::user::UserStatus::US_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal user.");
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (!u.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_user = true;
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (u.status == miku::user::UserStatus::US_FREEZE) {
          ret_msg = "用户已冻结";
          LogWarn("Freeze.");

          return miku::user::ErrNo::E_ALREADY;
        }

        if (u.status != miku::user::UserStatus::US_COMMON) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::user::ErrNo::E_STATUS;
        }

        if (u.type == miku::user::UserType::UT_COMMON) {
          UserRecord record;
          record.user_id = u.user_id;
          record.type = miku::user::UserOpType::UOP_FREEZE;
          record.attr = Json::objectValue;
          record.operator_id = request->operator_id();
          record.created = tnow;
          record.context = "";
          record.extension = Json::objectValue;
          record.Sign(ctx_.conf_.sign_key);

          u.status = miku::user::UserStatus::US_FREEZE;
          u.updated = tnow;
          u.Sign(ctx_.conf_.sign_key);

          sql_user = u.MakeUpdateSql(dtname);
          sql_record = record.MakeInsertSql(rtname);

          return 0;
        } else /* if (u.type == ....) { TODO 如果有其它类型 } else */ {
          ret_msg = "未知的用户类型";
          LogWarn("unknow user type.");
          return miku::user::ErrNo::E_ARGS;
        }
      },
      sql_user,
      sql_record);

  if (abnormal_user) {
    ctx_.UserAbnormal(user_id);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::user::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}

grpc::Status
UserServiceImpl::Unfreeze(grpc::ServerContext *context,
                          const miku::user::UnfreezeReq *request,
                          miku::user::UnfreezeResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::user::UnfreezeReq &req,
                              std::string *err_msg) -> bool {
    if (req.user_id() == 0) {
      *err_msg = "user_no not set.";
      return false;
    }

    if (req.operator_id() == 0) {
      *err_msg = "operator_id not set.";
      return false;
    }
    // 有些参数的检查需要等查到票的类型才可确定

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::user::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &user_id = request->user_id();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(user_id);
  std::string dtname = ctx_.UserTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_user;
  std::string sql_record;
  bool abnormal_user = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = User::SelectOne(h, dtname, 0, user_id, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::user::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::user::ErrNo::E_NOEXISTS;
        }

        auto &u = *d;
        if (u.status == miku::user::UserStatus::US_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal user.");
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (!u.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_user = true;
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (u.status == miku::user::UserStatus::US_COMMON) {
          ret_msg = "用户无需解冻";
          LogWarn("common user.");

          return miku::user::ErrNo::E_ALREADY;
        }

        if (u.status != miku::user::UserStatus::US_FREEZE) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::user::ErrNo::E_STATUS;
        }

        if (u.type == miku::user::UserType::UT_COMMON) {
          UserRecord record;
          record.user_id = u.user_id;
          record.type = miku::user::UserOpType::UOP_UNFREEZE;
          record.attr = Json::objectValue;
          record.operator_id = request->operator_id();
          record.created = tnow;
          record.context = "";
          record.extension = Json::objectValue;
          record.Sign(ctx_.conf_.sign_key);

          u.status = miku::user::UserStatus::US_COMMON;
          u.updated = tnow;
          u.Sign(ctx_.conf_.sign_key);

          sql_user = u.MakeUpdateSql(dtname);
          sql_record = record.MakeInsertSql(rtname);

          return 0;
        } else /* if (u.type == ....) { TODO 如果有其它类型 } else */ {
          ret_msg = "未知的券类型";
          LogWarn("unknow user type.");
          return miku::user::ErrNo::E_ARGS;
        }
      },
      sql_user,
      sql_record);

  if (abnormal_user) {
    ctx_.UserAbnormal(user_id);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::user::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}


grpc::Status
UserServiceImpl::Cancel(grpc::ServerContext *context,
                        const miku::user::CancelReq *request,
                        miku::user::CancelResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::user::CancelReq &req,
                              std::string *err_msg) -> bool {
    if (req.user_id() == 0) {
      *err_msg = "user_id not set.";
      return false;
    }

    if (req.operator_id() == 0) {
      *err_msg = "operator_id not set.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::user::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &user_id = request->user_id();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(user_id);
  std::string dtname = ctx_.UserTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_user;
  std::string sql_record;
  bool abnormal_user = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = User::SelectOne(h, dtname, 0, user_id, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::user::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::user::ErrNo::E_NOEXISTS;
        }

        auto &u = *d;
        if (u.status == miku::user::UserStatus::US_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal user.");
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (!u.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_user = true;
          return miku::user::ErrNo::E_DATA_INVALID;
        }

        if (u.status == miku::user::UserStatus::US_CANCEL) {
          ret_msg = "用户已销户";
          LogWarn("already cancel.");
          return miku::user::ErrNo::E_ALREADY;
        }

        if (u.status != miku::user::UserStatus::US_COMMON) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::user::ErrNo::E_STATUS;
        }

        UserRecord record;
        record.user_id = u.user_id;
        record.type = miku::user::UserOpType::UOP_CANCEL;
        record.attr = Json::objectValue;
        record.operator_id = request->operator_id();
        record.created = tnow;
        record.context = "";
        record.extension = Json::objectValue;
        record.Sign(ctx_.conf_.sign_key);

        u.status = miku::user::UserStatus::US_CANCEL;
        u.updated = tnow;
        u.Sign(ctx_.conf_.sign_key);

        sql_user = u.MakeUpdateSql(dtname);
        sql_record = record.MakeInsertSql(rtname);

        return 0;
      },
      sql_user,
      sql_record);

  if (abnormal_user) {
    ctx_.UserAbnormal(user_id);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::user::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}

grpc::Status
UserServiceImpl::Find(grpc::ServerContext *context,
                      const miku::user::FindReq *request,
                      miku::user::FindResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::user::FindReq &req,
                              std::string *err_msg) -> bool {
    if (req.user_id() == 0) {
      *err_msg = "user_id not set.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::user::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  const auto &user_id = request->user_id();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(user_id);
  std::string dtname = ctx_.UserTName(tindex);

  auto [ret, d] = User::SelectOne(dbproxy, dtname, 0, user_id);
  if (ret != 0) {  // 执行查询失败
    LogWarn("SelectOne failed." << ret);
    SET_REPLAY(miku::user::ErrNo::E_ERROR, "内部错误");
    return grpc::Status::OK;
  }

  if (!d) {  // 未查得数据
    LogWarn("not found data.");
    SET_REPLAY(miku::user::ErrNo::E_NOEXISTS, "数据未查得");
    return grpc::Status::OK;
  }

  auto &u = *d;
  if (u.status == miku::user::UserStatus::US_ABNORMAL) {
    LogWarn("abnormal user.");
    SET_REPLAY(miku::user::ErrNo::E_DATA_INVALID, "被破坏的数据");
    return grpc::Status::OK;
  }

  if (!u.CheckSign(ctx_.conf_.sign_key)) {
    LogWarn("error data.");
    ctx_.UserAbnormal(user_id);
    SET_REPLAY(miku::user::ErrNo::E_DATA_INVALID, "数据被破坏");
    return grpc::Status::OK;
  }

  if (u.status == miku::user::UserStatus::US_CANCEL) {
    LogWarn("already cancel.");
    SET_REPLAY(miku::user::ErrNo::E_ALREADY, "用户已销户");
    return grpc::Status::OK;
  }

  auto *user_info = reply->mutable_user_info();
  user_info->set_user_id(u.user_id);
  user_info->set_src_id(u.src_id);
  user_info->set_user_type(u.type);
  user_info->set_status(u.status);
  user_info->set_created(u.created);
  for (auto &[k, v] : ctx_.GetUserAttr(u)) {
    auto *pattrs = user_info->add_attrs();
    pattrs->set_k(std::move(k));
    pattrs->set_v(std::move(v));
  }
  SET_REPLAY(miku::user::ErrNo::E_SUCCESS, "");

  return grpc::Status::OK;
}
