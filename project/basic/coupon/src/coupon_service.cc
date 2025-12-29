#include "coupon_service.h"
#include "coupon.h"
#include "coupon_record.h"

#include <iostream>
#include <memory>
#include <string>
#include <sstream>
#include <optional>

#include "proto/coupon.grpc.pb.h"
#include "middle/redis_help.h"
#include "middle/mysql_help.h"
#include "middle/app_help.h"
#include "middle/auto_rpc_log.h"
#include "util/util.h"
#include "curl/curl.h"
#include "json/json.h"
#include "util/log.h"


#define SET_REPLAY(eno, emsg) do {      \
  reply->set_ret(eno);                  \
  reply->set_msg(emsg);                 \
} while (0)


CouponServiceContext::CouponServiceContext(const CouponServiceConfig &conf)
    : conf_(conf) {
}

std::string
CouponServiceContext::CouponTName(uint32_t idx) const {
  return conf_.table_bname + "_" +  std::to_string(idx);
}

std::string
CouponServiceContext::RecordTName(uint32_t idx, uint64_t tnow) const {
  return conf_.record_bname +
          "_" + std::to_string(idx) +
          "_" + miku::ts_to_year(tnow);
}

int32_t
CouponServiceContext::CouponAbnormal(const std::string &coupon_no) const {
  time_t tnow = time(nullptr);
  auto [dbproxy, sindex, tindex] = mysql_router.GetProxy(coupon_no);
  std::string dtname = CouponTName(tindex);
  std::string rtname = RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_coupon;
  std::string sql_record;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Coupon::SelectOne(h, dtname, 0, coupon_no, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::coupon::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::coupon::ErrNo::E_NOEXISTS;
        }

        auto &coup = *d;
        CouponRecord record;
        record.coupon_no = coup.coupon_no;
        record.type = miku::coupon::CouponOpType::COP_ABNORMAL;
        record.old_status = coup.status;
        record.new_status = miku::coupon::CouponStatus::CS_ABNORMAL;
        record.attr = Json::objectValue;
        record.operator_id = 1000;  // 只能系统检测到设置
        record.created = tnow;
        record.context = "";
        record.extension = Json::objectValue;
        record.Sign(conf_.sign_key);

        sql_coupon = coup.MakeAbnormalSql(dtname);
        sql_record = record.MakeInsertSql(rtname);

        return 0;
      },
      sql_coupon,
      sql_record);

  return ret;
}

int32_t
CouponServiceContext::CouponExpire(
        const std::string &coupon_no,
        const uint64_t operator_id,
        std::string *err_msg,
        const std::vector<std::pair<std::string, std::string>> &attrs) const {
  time_t tnow = time(nullptr);
  auto [dbproxy, sindex, tindex] = mysql_router.GetProxy(coupon_no);
  std::string dtname = CouponTName(tindex);
  std::string rtname = RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_coupon;
  std::string sql_record;
  bool abnormal_coupon = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Coupon::SelectOne(h, dtname, 0, coupon_no, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::coupon::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::coupon::ErrNo::E_NOEXISTS;
        }

        auto &coup = *d;
        if (coup.status == miku::coupon::CouponStatus::CS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal coupon.");
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        if (!coup.CheckSign(conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_coupon = true;
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        if (coup.status == miku::coupon::CouponStatus::CS_EXPIRE) {
          ret_msg = "券已过期";
          LogWarn("already expire.");
          return miku::coupon::ErrNo::E_ALREADY;
        }

        if (coup.status != miku::coupon::CouponStatus::CS_INIT &&
            coup.status != miku::coupon::CouponStatus::CS_INVOCATION) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::coupon::ErrNo::E_STATUS;
        }

        if (coup.expired >= tnow) {
          ret_msg = "未到过期条件";
          LogWarn("data not ready for op.");
          return miku::coupon::ErrNo::E_STATUS;
        }

        CouponRecord record;
        record.coupon_no = coup.coupon_no;
        record.type = miku::coupon::CouponOpType::COP_EXPIRE;
        record.old_status = coup.status;
        record.new_status = miku::coupon::CouponStatus::CS_EXPIRE;
        record.attr = coup.attr;
        record.operator_id = operator_id;
        record.created = tnow;
        record.context = "";
        record.extension = Json::objectValue;

        coup.status = miku::coupon::CouponStatus::CS_EXPIRE;
        coup.updated = tnow;

        if (attrs.size() > 0) {
          auto &coup_eattr = coup.attr["expire_attr"];
          auto &record_eattr = record.attr["expire_attr"];
          for (const auto &a : attrs) {
            coup_eattr[a.first] = a.second;
            record_eattr[a.first] = a.second;
          }
        }

        record.Sign(conf_.sign_key);
        coup.Sign(conf_.sign_key);

        sql_coupon = coup.MakeUpdateSql(dtname);
        sql_record = record.MakeInsertSql(rtname);

        return 0;
      },
      sql_coupon,
      sql_record);

  if (abnormal_coupon) {
    CouponAbnormal(coupon_no);
  }

  if (err_msg != nullptr) {
    *err_msg = std::move(ret_msg);
  }


  return ret;
}

CouponServiceImpl::CouponServiceImpl(const CouponServiceContext &ctx)
    : ctx_(ctx) {
}


grpc::Status
CouponServiceImpl::Create(grpc::ServerContext *context,
                          const miku::coupon::CreateReq *request,
                          miku::coupon::CreateResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::coupon::CreateReq &req,
                              std::string *err_msg) -> bool {
    if (req.coupon_no().empty()) {
      *err_msg = "coupon_no not set.";
      return false;
    }

    if (req.expire() == 0) {
      *err_msg = "expire not set.";
      return false;
    }

    if (req.type() == miku::coupon::CouponType::CT_NOTHRESHOLD) {
      const auto &conf = req.coupon_conf().no_threshold_info();
      if (conf.amount() == 0) {
        *err_msg = "amount can not be 0.";
        return false;
      }
    } else {
      *err_msg = "know coupon type.";
      return false;
    }
    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::coupon::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验
  time_t tnow = time(nullptr);
  if (request->expire() <= tnow) {
    SET_REPLAY(miku::coupon::ErrNo::E_ARGS, "无法创建已过期的券");
    return grpc::Status::OK;
  }

  // step 3 逻辑执行
  // copu创建
  Coupon coup;

  //coup.id = 0;  // 未设置
  coup.coupon_no = request->coupon_no();
  coup.activity_id = request->activity_id();
  coup.activity_cycle = request->activity_cycle();
  coup.type = request->type();
  coup.status = miku::coupon::CouponStatus::CS_INIT;
  coup.attr["amount"] = std::to_string(
                        request->coupon_conf().no_threshold_info().amount());
  coup.user_id = 0;
  coup.created = tnow;
  coup.updated = tnow;
  coup.started = 0;
  coup.expired = request->expire();
  coup.redemption = 0;
  coup.cancel = 0;
  coup.context = "";
  coup.extension = Json::objectValue;
  // coup.signature


  // record创建
  CouponRecord record;
  record.coupon_no = coup.coupon_no;
  record.type = miku::coupon::CouponOpType::COP_CREATE;
  record.old_status = miku::coupon::CouponStatus::CS_INIT;
  record.new_status = miku::coupon::CouponStatus::CS_INIT;
  record.attr = coup.attr;
  record.operator_id = request->operator_id();
  record.created = tnow;
  record.context = "";
  record.extension = Json::objectValue;
  // record.signature
  if (request->attrs_size() > 0) {
    auto &coup_cattr = coup.attr["create_attr"];
    auto &record_cattr = record.attr["create_attr"];
    for (const auto &a : request->attrs()) {
      coup_cattr[a.k()] = a.v();
      record_cattr[a.k()] = a.v();
    }
  }

  coup.Sign(ctx_.conf_.sign_key);
  record.Sign(ctx_.conf_.sign_key);


  auto [dbproxy, sindex, tindex] =
          ctx_.mysql_router.GetProxy(request->coupon_no());

  std::string dtname = ctx_.CouponTName(tindex);
  std::string sql_coupon = coup.MakeInsertSql(dtname);
  LogDebug("sql_coupon: " << sql_coupon);

  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string sql_record = record.MakeInsertSql(rtname);
  LogDebug("sql_record: " << sql_record);
  auto ret = dbproxy->Transaction({sql_coupon, sql_record});
  if (ret == ER_DUP_ENTRY) {  // 重复
    LogInfo("already exists.");
    SET_REPLAY(miku::coupon::ErrNo::E_EXISTS, "already exists.");
    return grpc::Status::OK;
  }

  if (ret != 0) {
    LogWarn("exec sql failed. sql:[" << sql_coupon << "]["
                                     << sql_record << "]");
    SET_REPLAY(miku::coupon::ErrNo::E_STATUS, "exec sql failed.");
    return grpc::Status::OK;
  }

  SET_REPLAY(miku::coupon::ErrNo::E_SUCCESS, "");
  return grpc::Status::OK;
}

grpc::Status
CouponServiceImpl::Invocation(grpc::ServerContext *context,
                              const miku::coupon::InvocationReq *request,
                              miku::coupon::InvocationResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::coupon::InvocationReq &req,
                              std::string *err_msg) -> bool {
    if (req.coupon_no().empty()) {
      *err_msg = "coupon_no not set.";
      return false;
    }

    if (req.user_id() == 0) {
      *err_msg = "user_id not set.";
      return false;
    }

    if (req.operator_id() == 0) {
      *err_msg = "operator_id not set.";
      return false;
    }

    if (req.end_ts() != 0 &&
          req.end_ts() < static_cast<uint64_t>(time(nullptr))) {
      *err_msg = "end_ts can not earlier than now.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::coupon::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &coupon_no = request->coupon_no();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(coupon_no);
  std::string dtname = ctx_.CouponTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_coupon;
  std::string sql_record;
  bool abnormal_coupon = false;
  bool expired_coupon = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Coupon::SelectOne(h, dtname, 0, coupon_no, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::coupon::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::coupon::ErrNo::E_NOEXISTS;
        }

        auto &coup = *d;
        if (coup.status == miku::coupon::CouponStatus::CS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal coupon.");
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        if (!coup.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_coupon = true;
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        const auto &user_id = request->user_id();
        if (coup.status == miku::coupon::CouponStatus::CS_INVOCATION) {
          if (coup.user_id == user_id) {  // 同一个人，可能重试
            ret_msg = "已被该用户启用";
            LogWarn("invocation by same uid.");
            return miku::coupon::ErrNo::E_ALREADY;
          } else {  // 被其它人激活
            ret_msg = "已被其它用户启用";
            LogWarn("invocation by other uid.");
            return miku::coupon::ErrNo::E_STATUS;
          }
        }

        if (coup.status != miku::coupon::CouponStatus::CS_INIT) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::coupon::ErrNo::E_STATUS;
        }

        if (coup.expired < tnow) {  // 券已过期
          ret_msg = "券已过期";
          LogWarn("error data.");
          expired_coupon = true;
          return miku::coupon::ErrNo::E_EXPIRE;
        }

        if (coup.activity_id != request->activity_id()) {
          ret_msg = "不匹配的领用";
          LogWarn("not match activity_id.");
          return miku::coupon::ErrNo::E_ARGS;
        }

        if (!request->activity_cycle().empty() &&
            coup.activity_cycle != request->activity_cycle()) {
          ret_msg = "不匹配的领用";
          LogWarn("not match activity_cycle.");
          return miku::coupon::ErrNo::E_ARGS;
        }

        CouponRecord record;
        record.coupon_no = coup.coupon_no;
        record.type = miku::coupon::CouponOpType::COP_INVOCATION;
        record.old_status = coup.status;
        record.new_status = miku::coupon::CouponStatus::CS_INVOCATION;
        record.attr["user_id"] = user_id;
        record.operator_id = request->operator_id();
        record.created = tnow;
        record.context = "";
        record.extension = Json::objectValue;

        coup.user_id = user_id;
        coup.status = miku::coupon::CouponStatus::CS_INVOCATION;
        coup.updated = tnow;
        if (request->start_ts() != 0) {
          coup.started = request->start_ts();
          record.attr["started"] = coup.started;
        } else {
          coup.started = tnow;
        }
        if (request->end_ts() != 0) {
          coup.expired = request->end_ts();
          record.attr["expired"] = coup.expired;
        }

        if (request->attrs_size() > 0) {
          auto &coup_iattr = coup.attr["invocation_attr"];
          auto &record_iattr = record.attr["invocation_attr"];
          for (const auto &a : request->attrs()) {
            coup_iattr[a.k()] = a.v();
            record_iattr[a.k()] = a.v();
          }
        }

        record.Sign(ctx_.conf_.sign_key);
        coup.Sign(ctx_.conf_.sign_key);

        sql_coupon = coup.MakeUpdateSql(dtname);
        sql_record = record.MakeInsertSql(rtname);

        return 0;
      },
      sql_coupon,
      sql_record);

  if (abnormal_coupon) {
    ctx_.CouponAbnormal(coupon_no);
  } else if (expired_coupon) {
    ctx_.CouponExpire(coupon_no);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::coupon::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }
  return grpc::Status::OK;
}

grpc::Status
CouponServiceImpl::Exchange(grpc::ServerContext *context,
                            const miku::coupon::ExchangeReq *request,
                            miku::coupon::ExchangeResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::coupon::ExchangeReq &req,
                              std::string *err_msg) -> bool {
    if (req.coupon_no().empty()) {
      *err_msg = "coupon_no not set.";
      return false;
    }

    if (req.activity_id().empty()) {
      *err_msg = "activity_id not set.";
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
    SET_REPLAY(miku::coupon::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &coupon_no = request->coupon_no();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(coupon_no);
  std::string dtname = ctx_.CouponTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_coupon;
  std::string sql_record;
  bool abnormal_coupon = false;
  bool expired_coupon = false;
  uint32_t amount = 0;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Coupon::SelectOne(h, dtname, 0, coupon_no, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::coupon::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::coupon::ErrNo::E_NOEXISTS;
        }

        auto &coup = *d;
        if (coup.status == miku::coupon::CouponStatus::CS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal coupon.");
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        if (!coup.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_coupon = true;
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        if (coup.status == miku::coupon::CouponStatus::CS_EXCHANGED) {
          ret_msg = "券已核销";
          LogWarn("Exchanged.");

          if (coup.type == miku::coupon::CouponType::CT_NOTHRESHOLD) {
            auto *info = reply->mutable_exchange_return()
                              ->mutable_no_threshold_info();
            amount = miku::cfg_get_ui(coup.attr, "amount", 0);
            info->set_amount(amount);
            info->set_operator_id(miku::cfg_get_ui(coup.attr, "operator_id", 0));
            info->set_exchange_timestamp(coup.redemption);

            reply->set_amount(amount);
          }
          return miku::coupon::ErrNo::E_ALREADY;
        }

        if (coup.status != miku::coupon::CouponStatus::CS_INVOCATION) {
          ret_msg = "不允许的操作状态";
          LogWarn("status not allow to op.");
          return miku::coupon::ErrNo::E_STATUS;
        }

        if (coup.expired < tnow) {  // 券已过期
          ret_msg = "券已过期";
          LogWarn("expire data.");
          expired_coupon = true;
          return miku::coupon::ErrNo::E_EXPIRE;
        }

        if (coup.activity_id != request->activity_id()) {
          ret_msg = "不匹配的核销";
          LogWarn("not match activity_id.");
          return miku::coupon::ErrNo::E_ARGS;
        }

        if (!request->activity_cycle().empty() &&
            coup.activity_cycle != request->activity_cycle()) {
          ret_msg = "不匹配的核销";
          LogWarn("not match activity_cycle.");
          return miku::coupon::ErrNo::E_ARGS;
        }

        if (coup.started > tnow) {  // 未到使用期
          ret_msg = "未到使用期";
          LogWarn("before the service period.");
          return miku::coupon::ErrNo::E_NOTINTIME;
        }

        if (coup.type == miku::coupon::CouponType::CT_NOTHRESHOLD) {
          CouponRecord record;
          record.coupon_no = coup.coupon_no;
          record.type = miku::coupon::CouponOpType::COP_EXCHANGE;
          record.old_status = coup.status;
          record.new_status = miku::coupon::CouponStatus::CS_EXCHANGED;
          record.attr["activity_cycle"] = request->activity_cycle();
          record.attr["trans_order_no"] = request->trans_order_no();
          record.attr["trans_order_amount"] = request->trans_order_amount();
          record.operator_id = request->operator_id();
          record.created = tnow;
          record.context = "";
          record.extension = Json::objectValue;

          coup.attr["operator_id"] = request->operator_id();
          coup.attr["trans_order_no"] = request->trans_order_no();
          coup.attr["trans_order_amount"] = request->trans_order_amount();
          coup.status = miku::coupon::CouponStatus::CS_EXCHANGED;
          coup.updated = tnow;
          coup.redemption = tnow;

          if (request->attrs_size() > 0) {
            auto &coup_eattr = coup.attr["exchange_attr"];
            auto &record_eattr = record.attr["exchange_attr"];
            for (const auto &a : request->attrs()) {
              coup_eattr[a.k()] = a.v();
              record_eattr[a.k()] = a.v();
            }
          }

          record.Sign(ctx_.conf_.sign_key);
          coup.Sign(ctx_.conf_.sign_key);

          sql_coupon = coup.MakeUpdateSql(dtname);
          sql_record = record.MakeInsertSql(rtname);

          auto *info = reply->mutable_exchange_return()
                            ->mutable_no_threshold_info();
          amount = miku::cfg_get_ui(coup.attr, "amount", 0);
          info->set_amount(amount);
          info->set_exchange_timestamp(coup.redemption);

          return 0;
        } else /* if (coup.type == ....) { TODO 如果有其它类型 } else */ {
          ret_msg = "未知的券类型";
          LogWarn("unknow coupon type.");
          return miku::coupon::ErrNo::E_ARGS;
        }
      },
      sql_coupon,
      sql_record);

  if (abnormal_coupon) {
    ctx_.CouponAbnormal(coupon_no);
  } else if (expired_coupon) {
    ctx_.CouponExpire(coupon_no);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::coupon::ErrNo>(ret));
    reply->set_msg(ret_msg);
  } else {
    reply->set_amount(amount);
  }

  return grpc::Status::OK;
}

grpc::Status
CouponServiceImpl::Cancel(grpc::ServerContext *context,
                          const miku::coupon::CancelReq *request,
                          miku::coupon::CancelResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::coupon::CancelReq &req,
                              std::string *err_msg) -> bool {
    if (req.coupon_no().empty()) {
      *err_msg = "coupon_no not set.";
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
    SET_REPLAY(miku::coupon::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  time_t tnow = time(nullptr);
  const auto &coupon_no = request->coupon_no();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(coupon_no);
  std::string dtname = ctx_.CouponTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_coupon;
  std::string sql_record;
  bool abnormal_coupon = false;
  bool expired_coupon = false;

  auto ret = dbproxy->TransactionProc(
      [&](miku::MysqlHandler *h) -> int32_t {
        auto [ret, d] = Coupon::SelectOne(h, dtname, 0, coupon_no, true);
        if (ret != 0) {  // 执行查询失败
          ret_msg = "内部错误";
          LogWarn("SelectOne failed." << ret);
          return miku::coupon::ErrNo::E_ERROR;
        }

        if (!d) {  // 未查得数据
          ret_msg = "数据未查得";
          LogWarn("not found data.");
          return miku::coupon::ErrNo::E_NOEXISTS;
        }

        auto &coup = *d;
        if (coup.status == miku::coupon::CouponStatus::CS_ABNORMAL) {
          ret_msg = "被破坏的数据";
          LogWarn("abnormal coupon.");
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        if (!coup.CheckSign(ctx_.conf_.sign_key)) {
          ret_msg = "数据被破坏";
          LogWarn("error data.");
          abnormal_coupon = true;
          return miku::coupon::ErrNo::E_DATA_INVALID;
        }

        if (coup.status == miku::coupon::CouponStatus::CS_CANCEL) {
          ret_msg = "券已作废";
          LogWarn("already cancel.");
          reply->set_cancel_timestamp(coup.cancel);
          return miku::coupon::ErrNo::E_ALREADY;
        }

        if (coup.status != miku::coupon::CouponStatus::CS_INIT) {
          if (coup.status != miku::coupon::CouponStatus::CS_INVOCATION ||
              !request->force()) {
            ret_msg = "不允许的操作状态";
            LogWarn("status not allow to op.");
            return miku::coupon::ErrNo::E_STATUS;
          }
        }

        if (coup.expired < tnow) {  // 券已过期
          ret_msg = "券已过期";
          LogWarn("error data.");
          expired_coupon = true;
          return miku::coupon::ErrNo::E_EXPIRE;
        }

        CouponRecord record;
        record.coupon_no = coup.coupon_no;
        record.type = miku::coupon::CouponOpType::COP_CANCEL;
        record.old_status = coup.status;
        record.new_status = miku::coupon::CouponStatus::CS_CANCEL;
        record.attr["force"] = request->force();
        record.operator_id = request->operator_id();
        record.created = tnow;
        record.context = "";
        record.extension = Json::objectValue;

        coup.status = miku::coupon::CouponStatus::CS_CANCEL;
        coup.updated = tnow;
        coup.cancel = tnow;

        if (request->attrs_size() > 0) {
          auto &coup_cattr = coup.attr["cancel_attr"];
          auto &record_cattr = record.attr["cancel_attr"];
          for (const auto &a : request->attrs()) {
            coup_cattr[a.k()] = a.v();
            record_cattr[a.k()] = a.v();
          }
        }


        record.Sign(ctx_.conf_.sign_key);
        coup.Sign(ctx_.conf_.sign_key);

        sql_coupon = coup.MakeUpdateSql(dtname);
        sql_record = record.MakeInsertSql(rtname);

        reply->set_cancel_timestamp(coup.cancel);
        return 0;
      },
      sql_coupon,
      sql_record);

  if (abnormal_coupon) {
    ctx_.CouponAbnormal(coupon_no);
  } else if (expired_coupon) {
    ctx_.CouponExpire(coupon_no);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::coupon::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }
  return grpc::Status::OK;
}

grpc::Status
CouponServiceImpl::Expire(grpc::ServerContext *context,
                          const miku::coupon::ExpireReq *request,
                          miku::coupon::ExpireResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::coupon::ExpireReq &req,
                              std::string *err_msg) -> bool {
    if (req.coupon_no().empty()) {
      *err_msg = "coupon_no not set.";
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
    SET_REPLAY(miku::coupon::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  const auto &coupon_no = request->coupon_no();
  std::string ret_msg;
  std::vector<std::pair<std::string, std::string>> attrs;
  if (request->attrs_size() > 0) {
    for (const auto &a : request->attrs()) {
      attrs.push_back(std::make_pair(a.k(), a.v()));
    }
  }

  auto ret = ctx_.CouponExpire(
      coupon_no, request->operator_id(), &ret_msg, attrs);

  if (ret != 0) {
    reply->set_ret(static_cast<miku::coupon::ErrNo>(ret));
    reply->set_msg(ret_msg);
  }
  return grpc::Status::OK;
}


grpc::Status
CouponServiceImpl::Find(grpc::ServerContext *context,
                        const miku::coupon::FindReq *request,
                        miku::coupon::FindResp *reply) {
  auto auto_print = AUTO_LOG_RPC(*request, *reply);
  static auto check_args = [](const miku::coupon::FindReq &req,
                              std::string *err_msg) -> bool {
    if (req.coupon_no().empty()) {
      *err_msg = "coupon_no not set.";
      return false;
    }

    return true;
  };

  std::string err_msg;
  // step 1 参数校验
  if (!check_args(*request, &err_msg)) {
    SET_REPLAY(miku::coupon::ErrNo::E_ARGS, err_msg);
    return grpc::Status::OK;
  }

  // step 2 业务参数校验

  // step 3 逻辑执行
  int32_t ret = 0;
  const auto &coupon_no = request->coupon_no();
  auto [dbproxy, sindex, tindex] = ctx_.mysql_router.GetProxy(coupon_no);
  time_t tnow = time(nullptr);
  std::string dtname = ctx_.CouponTName(tindex);
  std::string rtname = ctx_.RecordTName(tindex, tnow);
  std::string ret_msg;
  std::string sql_coupon;
  bool abnormal_coupon = false;
  bool expired_coupon = false;

  do {
    auto [r, d] = Coupon::SelectOne(dbproxy, dtname, 0, coupon_no);
    if (r != 0) {  // 执行查询失败
      ret_msg = "内部错误";
      LogWarn("SelectOne failed." << ret);
      ret = miku::coupon::ErrNo::E_ERROR;
      break;
    }

    if (!d) {  // 未查得数据
      ret_msg = "数据未查得";
      LogWarn("not found data.");
      ret = miku::coupon::ErrNo::E_NOEXISTS;
      break;
    }

    auto &coup = *d;
    if (coup.status == miku::coupon::CouponStatus::CS_ABNORMAL) {
      ret_msg = "被破坏的数据";
      LogWarn("abnormal coupon.");
      ret = miku::coupon::ErrNo::E_DATA_INVALID;
      break;
    }

    if (!coup.CheckSign(ctx_.conf_.sign_key)) {
      ret_msg = "数据被破坏";
      LogWarn("error data.");
      abnormal_coupon = true;
      ret = miku::coupon::ErrNo::E_DATA_INVALID;
      break;
    }

    auto *pcoupon_info = reply->mutable_coupon_info();
    pcoupon_info->set_id(coup.id);
    pcoupon_info->set_coupon_no(coup.coupon_no);
    pcoupon_info->set_activity_id(coup.activity_id);
    pcoupon_info->set_activity_cycle(coup.activity_cycle);
    pcoupon_info->set_type(coup.type);
    pcoupon_info->set_status(coup.status);
    pcoupon_info->set_user_id(coup.user_id);
    pcoupon_info->set_created(coup.created);
    pcoupon_info->set_updated(coup.updated);
    pcoupon_info->set_started(coup.started);
    pcoupon_info->set_expired(coup.expired);
    pcoupon_info->set_redemption(coup.redemption);
    pcoupon_info->set_cancel(coup.cancel);
    // attr
    static std::function<std::vector<std::pair<std::string, std::string>>(
          const Json::Value &, const std::string &)> get_attr_proc =
      [](
          const Json::Value &jv,
          const std::string &base) -> std::vector<std::pair<std::string, std::string>>{
        std::vector<std::pair<std::string, std::string>> vd;
        for (auto it = jv.begin(); it != jv.end(); ++it) {
          if (it->isString()) {
            vd.push_back(std::pair<std::string, std::string>(
                  base + it.name(), it->asString()));
          } else if (it->isIntegral()) {
            vd.push_back(std::pair<std::string, std::string>(
                  base + it.name(), std::to_string(it->asInt64())));
          } else if (it->isObject()) {
            auto sub_v = get_attr_proc(*it, base + it.name() + ".");
            vd.insert(vd.end(), sub_v.begin(), sub_v.end());
          } else if (it->isArray()) {
            // TODO
          }
        }

        return vd;
    };

    auto vattr = get_attr_proc(coup.attr, "");
    for (const auto &[k, v] : vattr) {
      auto *pattr = pcoupon_info->add_attrs();
      pattr->set_k(k);
      pattr->set_v(v);
    }
#if 0
    for (auto it = coup.attr.begin(); it != coup.attr.end(); ++it) {
      if (it->isString()) {
        auto *pattr = pcoupon_info->add_attrs();
        pattr->set_k(it.name());
        pattr->set_v(it->asString());
      } else if (it->isIntegral()) {
        auto *pattr = pcoupon_info->add_attrs();
        pattr->set_k(it.name());
        pattr->set_v(std::to_string(it->asInt64()));
      }
      // TODO obj的情况
    }
#endif

    ret = 0;
  } while (0);



  if (abnormal_coupon) {
    ctx_.CouponAbnormal(coupon_no);
  } else if (expired_coupon) {
    ctx_.CouponExpire(coupon_no);
  }

  if (ret != 0) {
    reply->set_ret(static_cast<miku::coupon::ErrNo>(ret));
    reply->set_msg(ret_msg);
  } else {
  }
  return grpc::Status::OK;
}


