#include "login_service.h"
#include "login.h"

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <optional>

#include "proto/login.grpc.pb.h"
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


LoginServiceContext::LoginServiceContext(const LoginServiceConfig &conf)
    : conf_(conf) {
}

std::string
LoginServiceContext::LoginTName(uint32_t idx) const {
  return conf_.table_bname + "_" +  std::to_string(idx);
}

int32_t
LoginServiceContext::LoginAbnormal(const std::string &appid,
                                   const std::string &auth_key) const {
  auto [dbproxy, sindex, tindex] = mysql_router.GetProxy(auth_key);
  std::string dtname = LoginTName(tindex);
  std::string ret_msg;
  std::string sql_login;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Login::SelectOne(h, dtname, 0, appid, auth_key, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::login::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::login::ErrNo::E_NOEXISTS;
        }

        auto &l = *d;

        sql_login = l.MakeAbnormalSql(dtname);

        return 0;
      },
      sql_login);

  return ret;
}

std::optional<std::string>
LoginServiceContext::EncryptData(const std::string &r,
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
LoginServiceContext::DecryptData(const std::string &e,
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

std::string
LoginServiceContext::HashData(const std::string &r,
                              const std::string &s) const {
  char buf[45] = "";
  miku_b64_sm3(reinterpret_cast<const uint8_t*>(r.c_str()),
               r.length(),
               reinterpret_cast<const uint8_t *>(s.c_str()),
               s.length(),
               buf,
               sizeof(buf));

  return std::string(buf);
}

bool
LoginServiceContext::AddLoginAttr(
    Login *pl,
    const std::string &k,
    const std::string &v,
    const int32_t &op) const {
  assert(pl != nullptr);

  const auto &l = *pl;  // 这里不改值
  const auto *pkconf = LoginAttrKeyConfig::get_key_config(k);
  if (pkconf == nullptr) {
    return false;
  }

  auto &jl = pl->attr;

  const std::string *pd = nullptr;
  std::optional<std::string> oev = std::nullopt;
  if (pkconf->enc_type == LoginAttrKeyConfig::ENC_TYPE_ENC) {
    oev = EncryptData(v, l.salt);
    if (!oev) {
      LogWarn("EncryptData failed.");
      return false;
    }
    pd = &(*oev);
  } else if (pkconf->enc_type == LoginAttrKeyConfig::ENC_TYPE_HASH) {
    oev = HashData(v, l.salt);
    pd = &(*oev);
  } else {
    pd = &v;
  }
  const auto &d = *pd;

  bool update = false;
  if (pkconf->multiple) {
    if (jl.isMember(k.c_str()) && !jl[k].isArray()) {  // 类型判断，只会做删除
      jl.removeMember(k.c_str());
      update = true;  // 这里有做数据更新
    }

    bool has = miku::json_sarr_has_value(jl[k], d);
    if (op == 0) {  // 增加
      if (has) {
        return false;
      }
      jl[k].append(d);
      return true;
    } else {  // 减少
      if (!has) {
        return update;
      }

      miku::json_sarr_remove_value(&jl[k], d);
      if (jl[k].isArray() && jl[k].size() == 0) {  // 删掉
        jl.removeMember(k.c_str());
      }
      return true;
    }
  } else {
    bool has = false;
    if (jl.isMember(k.c_str())) {  // 类型判断，只会做删除
      if (!jl[k].isString()) {
        jl.removeMember(k.c_str());
        update = true;
      } else {
        has = (jl[k] == d);
      }
    }

    if (op == 0) {  // 增加
      if (has) {  // 已存在
        return false;
      }
      jl[k] = d;
      return true;
    } else {  // 减少
      if (!has) {
        return update;
      }
      jl.removeMember(k.c_str());
      return true;
    }
  }

  return true;
}

std::vector<std::pair<std::string, std::string>>
LoginServiceContext::GetLoginAttr(const Login &l) const {
  std::vector<std::pair<std::string, std::string>> vr;
  static auto set_attr = [](
      const LoginServiceContext *pctx,
      std::vector<std::pair<std::string, std::string>> *pvr,
      const Json::Value &jv,
      const std::string &salt) -> void {
    for (auto it = jv.begin(); it != jv.end(); ++it) {
      const std::string &k = it.name();
      const auto *pkconf = LoginAttrKeyConfig::get_key_config(k);
      if (pkconf == nullptr) {
        continue;
      }
      if (pkconf->multiple) {
        if (it->isArray()) {
          for (const auto &v : *it) {
            if (v.isString()) {
              if (pkconf->enc_type == LoginAttrKeyConfig::ENC_TYPE_ENC) {
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
        if (pkconf->enc_type == LoginAttrKeyConfig::ENC_TYPE_ENC) {
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
  set_attr(this, &vr, l.attr, l.salt);

  return vr;
}

LoginServiceImpl::LoginServiceImpl(const LoginServiceContext &ctx)
    : ctx_(ctx) {
}


grpc::Status
LoginServiceImpl::Register(grpc::ServerContext *context,
                           const miku::login::RegisterReq *request,
                           miku::login::RegisterResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::login::RegisterReq &req,
                              std::string *err_msg) -> bool {
    if (req.auth_key().empty()) {
      *err_msg = "auth_key not set.";
      return false;
    }

    if (req.type() == miku::login::LoginType::LT_COMMON) {
      bool find_auth_secret = false;
      for (const auto &p : req.attrs()) {
        if (p.k() == std::string(LoginAttrKeyConfig::key_auth) &&
              !p.v().empty()) {
          find_auth_secret = true;
          break;
        }
      }
      if (!find_auth_secret) {
        *err_msg = "auth_secret not set.";
        return false;
      }
    } else if (req.type() == miku::login::LoginType::LT_ALREADY) {
      // nothing
    } else /* if (req.type() == ??) {} */ {
      *err_msg = "know login type.";
      return false;
    }

    if (req.user_id() == 0) {
      *err_msg = "user_id not set.";
      return false;
    }

    for (const auto &p : req.attrs()) {
      const auto &k = p.k();
      if (!LoginAttrKeyConfig::is_valid_key(k)) {
        *err_msg = "key " + k + " can not set.";
        return false;
      }
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  // Login创建
  ::Login l;

  //l.id = 0;  // 不设置
  l.appid = request->appid();
  l.salt = miku::make_random_string();
  l.type = request->type();
  l.auth_key = request->auth_key();
  l.status = miku::login::LoginStatus::LS_COMMON;
  l.attr = Json::objectValue;
  for (const auto &a : request->attrs()) {
    ctx_.AddLoginAttr(&l, a.k(), a.v(), a.op());
  }
  l.param = Json::objectValue;
  for (const auto &p : request->params()) {
    if (!p.k().empty()) {
      l.param[p.k()] = p.v();
    }
  }
  l.user_id = request->user_id();
  l.created = tnow;
  l.updated = tnow;
  l.context = "";
  l.extension = Json::objectValue;
  // l.signature

  l.Sign(ctx_.conf_.sign_key);

  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(l.auth_key);

  std::string dtname = ctx_.LoginTName(tindex);
  std::string sql_login = l.MakeInsertSql(dtname);
  LogDebug("sql_login: " << sql_login);

  auto ret = dbproxy->ExecuteQuery(sql_login);
  if (ret == ER_DUP_ENTRY) {  // 重复
    LogInfo("already exists.");
    SET_REPLAY(miku::login::ErrNo::E_EXISTS, "id已被占用.");
    return grpc::Status::OK;
  }

  if (ret != 0) {
    LogWarn("exec sql failed. sql:[" << sql_login<< "]");
    SET_REPLAY(miku::login::ErrNo::E_STATUS, "exec sql failed.");
    return grpc::Status::OK;
  }

  SET_REPLAY(miku::login::ErrNo::E_SUCCESS, "");
  return grpc::Status::OK;
}


grpc::Status
LoginServiceImpl::Login(grpc::ServerContext *context,
                        const miku::login::LoginReq *request,
                        miku::login::LoginResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::login::LoginReq &req,
                              std::string *err_msg) -> bool {
    if (req.auth_key().empty()) {
      *err_msg = "auth_key not set.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  const auto &appid = request->appid();
  const auto &auth_key = request->auth_key();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(auth_key);
  std::string dtname = ctx_.LoginTName(tindex);

  auto [ret, d] = Login::SelectOne(dbproxy, dtname, 0, appid, auth_key);
  if (ret != 0) {
    LogWarn("SelectOne failed." << ret);
    SET_REPLAY(miku::login::ErrNo::E_ERROR, "查询数据失败");
    return grpc::Status::OK;
  }
  if (!d) {  // 未查得数据
    LogWarn("not found data.");
    SET_REPLAY(miku::login::ErrNo::E_NOEXISTS, "数据未查得");
    return grpc::Status::OK;
  }

  auto &l = *d;
  if (l.status == miku::login::LoginStatus::LS_ABNORMAL) {
    LogWarn("abnormal login info.");
    SET_REPLAY(miku::login::ErrNo::E_DATA_INVALID, "被破坏的数据");
    return grpc::Status::OK;
  }

  if (!l.CheckSign(ctx_.conf_.sign_key)) {
    LogWarn("error data.");
    ctx_.LoginAbnormal(appid, auth_key);
    SET_REPLAY(miku::login::ErrNo::E_DATA_INVALID, "数据被破坏");
    return grpc::Status::OK;
  }

  if (l.status == miku::login::LoginStatus::LS_CANCEL) {
    LogWarn("already cancel.");
    SET_REPLAY(miku::login::ErrNo::E_STATUS, "用户已销户");
    return grpc::Status::OK;
  }

  if (l.status == miku::login::LoginStatus::LS_FREEZE) {
    LogWarn("Freeze.");
    SET_REPLAY(miku::login::ErrNo::E_STATUS, "用户已冻结");
    return grpc::Status::OK;
  }

  if (l.status != miku::login::LoginStatus::LS_COMMON) {
    LogWarn("not LS_COMMON.");
    SET_REPLAY(miku::login::ErrNo::E_STATUS, "不允许操作的状态");
    return grpc::Status::OK;
  }

  if (l.type == miku::login::LoginType::LT_COMMON) {
    const std::string *pauth_string = nullptr;
    for (const auto &p : request->attrs()) {
      if (p.k() == std::string(LoginAttrKeyConfig::key_auth)) {
        pauth_string = &p.v();
        break;
      }
    }

    if (pauth_string == nullptr ||
        !l.attr.isMember(LoginAttrKeyConfig::key_auth) ||
        !l.attr[LoginAttrKeyConfig::key_auth].isString() ||
        l.attr[LoginAttrKeyConfig::key_auth].asString() !=
          ctx_.HashData(*pauth_string, l.salt)) {
      SET_REPLAY(miku::login::ErrNo::E_NOAUTH, "密码不正确");
      LogWarn("check auth_secret failed.");
      return grpc::Status::OK;
    }
  } else if (l.type == miku::login::LoginType::LT_ALREADY) {
    // nothing
  } else {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, "未知的登录类型");
    LogWarn("unknow login type.");
    return grpc::Status::OK;
  }

  reply->set_user_id(l.user_id);
  SET_REPLAY(miku::login::ErrNo::E_SUCCESS, "");

  return grpc::Status::OK;
}

grpc::Status
LoginServiceImpl::Update(grpc::ServerContext *context,
                         const miku::login::UpdateReq *request,
                         miku::login::UpdateResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::login::UpdateReq &req,
                              std::string *err_msg) -> bool {
    if (req.auth_key().empty()) {
      *err_msg = "auth_key not set.";
      return false;
    }

    for (const auto &p : req.attrs()) {
      const auto &k = p.k();
      if (!LoginAttrKeyConfig::is_valid_key(k)) {
        *err_msg = "key " + k + " can not set.";
        return false;
      }
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }


  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &appid = request->appid();
  const auto &auth_key = request->auth_key();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(auth_key);
  std::string dtname = ctx_.LoginTName(tindex);
  std::string ret_msg;
  std::string sql_login;
  bool abnormal_login = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Login::SelectOne(h, dtname, 0, appid, auth_key, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::login::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::login::ErrNo::E_NOEXISTS;
        }

        auto &l = *d;
        if (l.status == miku::login::LoginStatus::LS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal login info.");
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (!l.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_login = true;
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (l.status != miku::login::LoginStatus::LS_COMMON) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::login::ErrNo::E_STATUS;
        }

        bool lupdate = false;
        if (request->user_id() != 0) {
          if (l.user_id != request->user_id()) {
            l.user_id = request->user_id();
            lupdate = true;
          }
        }

        for (const auto &p : request->attrs()) {
          lupdate = ctx_.AddLoginAttr(&l, p.k(), p.v(), p.op());
        }

        l.updated = tnow;
        l.Sign(ctx_.conf_.sign_key);

        if (lupdate) {
          sql_login = l.MakeUpdateSql(dtname);
        } else {
          sql_login = "";
        }

        return 0;
      },
      sql_login);

  if (abnormal_login) {
    ctx_.LoginAbnormal(appid, auth_key);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::login::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}

grpc::Status
LoginServiceImpl::Freeze(grpc::ServerContext *context,
                         const miku::login::FreezeReq *request,
                         miku::login::FreezeResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::login::FreezeReq &req,
                              std::string *err_msg) -> bool {
    if (req.auth_key().empty()) {
      *err_msg = "auth_key not set.";
      return false;
    }

    // 有些参数的检查需要等查到票的类型才可确定
    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &appid = request->appid();
  const auto &auth_key = request->auth_key();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(auth_key);
  std::string dtname = ctx_.LoginTName(tindex);
  std::string ret_msg;
  std::string sql_login;
  std::string sql_record;
  bool abnormal_login = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Login::SelectOne(h, dtname, 0, appid, auth_key, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::login::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::login::ErrNo::E_NOEXISTS;
        }

        auto &l = *d;
        if (l.status == miku::login::LoginStatus::LS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal login info.");
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (!l.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_login = true;
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (l.status == miku::login::LoginStatus::LS_FREEZE) {
          ret_msg = "已冻结";
          LogWarn("Freeze.");

          return miku::login::ErrNo::E_ALREADY;
        }

        if (l.status != miku::login::LoginStatus::LS_COMMON) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::login::ErrNo::E_STATUS;
        }

        if (l.type == miku::login::LoginType::LT_COMMON ||
            l.type == miku::login::LoginType::LT_ALREADY) {
          l.status = miku::login::LoginStatus::LS_FREEZE;
          l.updated = tnow;
          l.Sign(ctx_.conf_.sign_key);

          sql_login = l.MakeUpdateSql(dtname);

          return 0;
        } else /* if (l.type == ....) { TODO 如果有其它类型 } else */ {
          ret_msg = "未知的登录类型";
          LogWarn("unknow login type.");
          return miku::login::ErrNo::E_ARGS;
        }
      },
      sql_login);

  if (abnormal_login) {
    ctx_.LoginAbnormal(appid, auth_key);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::login::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}

grpc::Status
LoginServiceImpl::Unfreeze(grpc::ServerContext *context,
                           const miku::login::UnfreezeReq *request,
                           miku::login::UnfreezeResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::login::UnfreezeReq &req,
                              std::string *err_msg) -> bool {
    if (req.auth_key().empty()) {
      *err_msg = "auth_key not set.";
      return false;
    }
    // 有些参数的检查需要等查到票的类型才可确定

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &appid = request->appid();
  const auto &auth_key = request->auth_key();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(auth_key);
  std::string dtname = ctx_.LoginTName(tindex);
  std::string ret_msg;
  std::string sql_login;
  bool abnormal_login = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Login::SelectOne(h, dtname, 0, appid, auth_key, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::login::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::login::ErrNo::E_NOEXISTS;
        }

        auto &l = *d;
        if (l.status == miku::login::LoginStatus::LS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal login info.");
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (!l.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_login = true;
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (l.status == miku::login::LoginStatus::LS_COMMON) {
          ret_msg = "无需解冻";
          LogWarn("common login info.");

          return miku::login ::ErrNo::E_ALREADY;
        }

        if (l.status != miku::login::LoginStatus::LS_FREEZE) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::login::ErrNo::E_STATUS;
        }

        if (l.type == miku::login::LoginType::LT_COMMON ||
            l.type == miku::login::LoginType::LT_ALREADY) {
          l.status = miku::login::LoginStatus::LS_COMMON;
          l.updated = tnow;
          l.Sign(ctx_.conf_.sign_key);

          sql_login = l.MakeUpdateSql(dtname);

          return 0;
        } else /* if (l.type == ....) { TODO 如果有其它类型 } else */ {
          ret_msg = "未知的券类型";
          LogWarn("unknow login type.");
          return miku::login::ErrNo::E_ARGS;
        }
      },
      sql_login);

  if (abnormal_login) {
    ctx_.LoginAbnormal(appid, auth_key);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::login::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}


grpc::Status
LoginServiceImpl::Cancel(grpc::ServerContext *context,
                         const miku::login::CancelReq *request,
                         miku::login::CancelResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::login::CancelReq &req,
                              std::string *err_msg) -> bool {
    if (req.auth_key().empty()) {
      *err_msg = "auth_key not set.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &appid = request->appid();
  const auto &auth_key = request->auth_key();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(auth_key);
  std::string dtname = ctx_.LoginTName(tindex);
  std::string ret_msg;
  std::string sql_login;
  bool abnormal_login = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Login::SelectOne(h, dtname, 0, appid, auth_key, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::login::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::login::ErrNo::E_NOEXISTS;
        }

        auto &l = *d;
        if (l.status == miku::login::LoginStatus::LS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal login info.");
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (!l.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_login = true;
          return miku::login::ErrNo::E_DATA_INVALID;
        }

        if (l.status == miku::login::LoginStatus::LS_CANCEL) {
          ret_msg = "已销户";
          LogWarn("already cancel.");
          return miku::login::ErrNo::E_ALREADY;
        }

        if (l.status != miku::login::LoginStatus::LS_COMMON) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::login::ErrNo::E_STATUS;
        }

        l.status = miku::login::LoginStatus::LS_CANCEL;
        l.updated = tnow;
        l.Sign(ctx_.conf_.sign_key);

        sql_login = l.MakeUpdateSql(dtname);

        return 0;
      },
      sql_login);

  if (abnormal_login) {
    ctx_.LoginAbnormal(appid, auth_key);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::login::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }

  return grpc::Status::OK;
}

grpc::Status
LoginServiceImpl::Find(grpc::ServerContext *context,
                      const miku::login::FindReq *request,
                      miku::login::FindResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::login::FindReq &req,
                              std::string *err_msg) -> bool {
    if (req.auth_key().empty()) {
      *err_msg = "auth_key not set.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::login::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  const auto &appid = request->appid();
  const auto &auth_key = request->auth_key();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(auth_key);
  std::string dtname = ctx_.LoginTName(tindex);

  auto [ret, d] = Login::SelectOne(dbproxy, dtname, 0, appid, auth_key);
  if (ret != 0) {  // 执行查询失败
    LogWarn("SelectOne failed." << ret);
    SET_REPLAY(miku::login::ErrNo::E_ERROR, "内部错误");
    return grpc::Status::OK;
  }

  if (!d) {  // 未查得数据
    LogWarn("not found data.");
    SET_REPLAY(miku::login::ErrNo::E_NOEXISTS, "数据未查得");
    return grpc::Status::OK;
  }

  auto &l = *d;
  if (l.status == miku::login::LoginStatus::LS_ABNORMAL) {
    LogWarn("abnormal login info.");
    SET_REPLAY(miku::login::ErrNo::E_DATA_INVALID, "被破坏的数据");
    return grpc::Status::OK;
  }

  if (!l.CheckSign(ctx_.conf_.sign_key)) {
    LogWarn("error data.");
    ctx_.LoginAbnormal(appid, auth_key);
    SET_REPLAY(miku::login::ErrNo::E_DATA_INVALID, "数据被破坏");
    return grpc::Status::OK;
  }

  auto *login_info = reply->mutable_login_info();
  login_info->set_appid(l.appid);
  login_info->set_type(static_cast<miku::login::LoginType>(l.type));
  login_info->set_auth_key(l.auth_key);
  login_info->set_status(l.status);
  login_info->set_user_id(l.user_id);
  login_info->set_created(l.created);
  for (auto &[k, v] : ctx_.GetLoginAttr(l)) {
    auto *pattrs = login_info->add_attrs();
    pattrs->set_k(std::move(k));
    pattrs->set_v(std::move(v));
  }
  for (auto it = l.param.begin(); it != l.param.end(); ++it) {
    if (it->isString()) {
      auto *pparams = login_info->add_params();
      pparams->set_k(it.name());
      pparams->set_v(it->asString());
    }
  }
  SET_REPLAY(miku::login::ErrNo::E_SUCCESS, "");

  return grpc::Status::OK;
}
