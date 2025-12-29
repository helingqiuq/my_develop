#include "coupon.h"

#include <sstream>

#include "encrypt_help/hash.h"
#include "util/util.h"
#include "util/log.h"
#include "middle/mysql_help.h"
#include "proto/coupon.grpc.pb.h"

const char *Coupon::select_column =
               " `id`"
               ",`coupon_no`"
               ",`activity_id`"
               ",`activity_cycle`"
               ",`type`"
               ",`status`"
               ",`attr`"
               ",`user_id`"
               ",UNIX_TIMESTAMP(`created`)"
               ",UNIX_TIMESTAMP(`updated`)"
               ",UNIX_TIMESTAMP(`started`)"
               ",UNIX_TIMESTAMP(`expired`)"
               ",UNIX_TIMESTAMP(`redemption`)"
               ",UNIX_TIMESTAMP(`cancel`)"
               ",`context`"
               ",`extension`"
               ",`signature`";

std::string
Coupon::MakeSign(const Coupon &c, const std::string &sign_key) {
  std::stringstream ss;
  ss << c.coupon_no
     << c.activity_id
     << c.activity_cycle
     << c.type
     << c.status
     << miku::json_to_string(c.attr)
     << c.user_id
     << c.created
     << c.updated
     << c.started
     << c.expired
     << c.redemption
     << c.cancel;

  std::string sign_str = ss.str();
  char buf[45] = "";
  miku_b64_sm3(reinterpret_cast<const uint8_t*>(sign_str.c_str()),
               sign_str.length(),
               reinterpret_cast<const uint8_t *>(sign_key.c_str()),
               sign_key.length(),
               buf,
               sizeof(buf));

  return std::string(buf);
}

void
Coupon::Sign(const std::string &sign_key) {
  std::string s = MakeSign(*this, sign_key);
  this->signature = s;
}

bool
Coupon::CheckSign(const std::string &sign_key) const {
  std::string s = MakeSign(*this, sign_key);
  return s == this->signature;
}


std::string
Coupon::MakeInsertSql(const std::string &tname) const {
  std::stringstream ss_column;
  std::stringstream ss_value;
  ss_column << "`coupon_no`";
  ss_value << miku::mysql_help_quote_string(coupon_no);
  ss_column << ",`activity_id`";
  ss_value << "," << miku::mysql_help_quote_string(activity_id);
  ss_column << ",`activity_cycle`";
  ss_value << "," << miku::mysql_help_quote_string(activity_cycle);
  ss_column << ",`type`";
  ss_value << "," << type;
  ss_column << ",`status`";
  ss_value << "," << status;
  ss_column << ",`attr`";
  ss_value << "," << miku::mysql_help_quote_string(miku::json_to_string(attr));
  ss_column << ",`user_id`";
  ss_value << "," << user_id;
  ss_column << ",`created`";
  ss_value << ",FROM_UNIXTIME(" << created << ")";
  ss_column << ",`updated`";
  ss_value << ",FROM_UNIXTIME(" << updated << ")";
  ss_column << ",`started`";
  ss_value << ",FROM_UNIXTIME(" << started << ")";
  ss_column << ",`expired`";
  ss_value << ",FROM_UNIXTIME(" << expired << ")";
  ss_column << ",`redemption`";
  ss_value << ",FROM_UNIXTIME(" << redemption << ")";
  ss_column << ",`cancel`";
  ss_value << ",FROM_UNIXTIME(" << cancel << ")";
  ss_column << ",`context`";
  ss_value << "," << miku::mysql_help_quote_string(context);
  ss_column << ",`extension`";
  ss_value << "," << miku::mysql_help_quote_string(
                      miku::json_to_string(extension));
  ss_column << ",`signature`";
  ss_value << "," << miku::mysql_help_quote_string(signature);

  std::stringstream ss_sql;
  ss_sql << "INSERT INTO `" << tname << "`("
         << ss_column.str() << ")"
         << " VALUES ("
         << ss_value.str() << ")";
  return ss_sql.str();
}

std::string
Coupon::MakeUpdateSql(const std::string &tname) const {
  std::stringstream ss_update;
  ss_update
    << "UPDATE `" << tname << "` SET"
    << " `status`=" << status
    << ",`attr`=" << miku::mysql_help_quote_string(miku::json_to_string(attr))
    << ",`user_id`=" << user_id
    << ",`updated`=FROM_UNIXTIME(" << updated << ")"
    << ",`started`=FROM_UNIXTIME(" << started << ")"
    << ",`expired`=FROM_UNIXTIME(" << expired << ")"
    << ",`redemption`=FROM_UNIXTIME(" << redemption << ")"
    << ",`cancel`=FROM_UNIXTIME(" << cancel << ")"
    << ",`context`=" << miku::mysql_help_quote_string(context)
    << ",`extension`=" << miku::mysql_help_quote_string(
                            miku::json_to_string(extension))
    << ",`signature`=" << miku::mysql_help_quote_string(signature)
    << " WHERE `id`=" << id
    << " AND `coupon_no`=" << miku::mysql_help_quote_string(coupon_no);

  return ss_update.str();
}

std::string
Coupon::MakeAbnormalSql(const std::string &tname) const {
  std::stringstream ss_abnormal;
  ss_abnormal
    << "UPDATE `" << tname << "` SET"
    << " `status`=" << miku::coupon::CouponStatus::CS_ABNORMAL
    << " WHERE `id`=" << id
    << " AND `coupon_no`=" << miku::mysql_help_quote_string(coupon_no);

  return ss_abnormal.str();
}

std::optional<std::vector<Coupon>>
Coupon::Select(miku::MysqlHandler *h,
               const std::string &tname,
               const std::vector<std::string> &and_cond,
               const std::vector<std::string> &or_cond,
               int32_t page_idx,
               int32_t page_size) {
  std::stringstream ss_select;
  ss_select << "SELECT " << select_column
            << " FROM " << tname
            << " WHERE 1=1";
  for (const auto &s : and_cond) {
    ss_select << " AND " << s;
  }

  if (or_cond.size() > 0) {
    ss_select << " AND (1=0";
    for (const auto &s : or_cond) {
      ss_select << " OR " << s;
    }
    ss_select << ")";
  }
  ss_select << " LIMIT " << page_idx * page_size << "," << page_size;

  std::string select_sql = ss_select.str();
  LogDebug("select sql = " << select_sql);

  auto mysql_result_help = h->SelectData(select_sql);
  if (!mysql_result_help->Ok()) {
    LogWarn("h->SelectData failed.");
    return std::nullopt;
  }

  std::vector<Coupon> dv;
  auto *mysql_reply = mysql_result_help->Reply();
  MYSQL_ROW row;
  while ((row = mysql_fetch_row(mysql_reply))) {
    Coupon c;
    c.FromMysqlReuslt(row);
    dv.push_back(std::move(c));
  }

  return dv;
}

std::optional<std::vector<Coupon>>
Coupon::Select(std::shared_ptr<miku::MysqlProxy> &proxy,
               const std::string &tname,
               const std::vector<std::string> &and_cond,
               const std::vector<std::string> &or_cond,
               int32_t page_idx,
               int32_t page_size) {
  auto h = proxy->GetHandler();
  auto r = Select(h.get(), tname, and_cond, or_cond, page_idx, page_size);
  proxy->PutHandler(h);
  return r;
}


std::string
Coupon::DebugString() const {
  std::stringstream ss;
  ss << "id = " << id << std::endl
     << "coupon_no = " << coupon_no << std::endl
     << "activity_id = " << activity_id << std::endl
     << "activity_cycle = " << activity_cycle << std::endl
     << "type = " << type << std::endl
     << "status = " << status << std::endl
     << "attr = " << miku::json_to_string(attr) << std::endl
     << "user_id = " << user_id << std::endl
     << "created = " << created << std::endl
     << "updated = " << updated << std::endl
     << "started = " << started << std::endl
     << "expired = " << expired << std::endl
     << "redemption = " << redemption << std::endl
     << "cancel = " << cancel << std::endl
     << "context = " << context << std::endl
     << "extension = " << miku::json_to_string(extension) << std::endl
     << "signature = " << signature;
  return ss.str();
}

bool
Coupon::FromMysqlReuslt(MYSQL_ROW row) {
  if (!row) {
    return false;
  }

  this->id = strtoull(row[0], nullptr, 10);
  this->coupon_no = row[1];
  this->activity_id = row[2];
  this->activity_cycle = row[3];
  this->type = atoi(row[4]);
  this->status = atoi(row[5]);
  auto jattr = miku::json_from_string(row[6]);
  this->attr = jattr ? std::move(*jattr) : Json::objectValue;
  this->user_id = strtoull(row[7], nullptr, 10);
  this->created = strtoull(row[8], nullptr, 10);
  this->updated = strtoull(row[9], nullptr, 10);
  this->started = strtoull(row[10], nullptr, 10);
  this->expired = strtoull(row[11], nullptr, 10);
  this->redemption = strtoull(row[12], nullptr, 10);
  this->cancel = strtoull(row[13], nullptr, 10);
  this->context = row[14];
  auto jextension = miku::json_from_string(row[15]);
  this->extension = jextension ? std::move(*jextension) : Json::objectValue;
  this->signature = row[16];

  return true;
}

std::tuple<int32_t, std::optional<Coupon>>
Coupon::SelectOne(miku::MysqlHandler *h,
                  const std::string &tname,
                  uint64_t id,
                  const std::string &coupon_no,
                  bool for_update) {
  if (id == 0 && coupon_no.empty()) {
    LogWarn("id and coupon_no must set one.");
    return {miku::coupon::ErrNo::E_ARGS, std::nullopt};
  }

  std::stringstream ss_select;
  ss_select << "SELECT " << select_column
            << " FROM " << tname
            << " WHERE 1=1";
  if (id != 0) {
    ss_select << " AND `id`=" << id;
  }
  if (!coupon_no.empty()) {
    ss_select << " AND `coupon_no`="
              << miku::mysql_help_quote_string(coupon_no);
  }

  if (for_update) {
    ss_select << " FOR UPDATE";
  }

  std::string select_sql = ss_select.str();
  LogDebug("select sql = " << select_sql);

  auto mysql_result_help = h->SelectData(select_sql);
  if (!mysql_result_help->Ok()) {
    LogWarn("h->SelectData failed.");
    return {h->LastErrno(), std::nullopt};
  }

  std::vector<Coupon> dv;
  auto *mysql_reply = mysql_result_help->Reply();
  MYSQL_ROW row = mysql_fetch_row(mysql_reply);
  if (!row) {
    return {0, std::nullopt};
  }

  Coupon c;
  c.FromMysqlReuslt(row);
  return {0, c};
}

std::tuple<int32_t, std::optional<Coupon>>
Coupon::SelectOne(std::shared_ptr<miku::MysqlProxy> &proxy,
                  const std::string &tname,
                  uint64_t id,
                  const std::string &coupon_no,
                  bool for_update) {
  auto h = proxy->GetHandler();
  auto r = SelectOne(h.get(), tname, id, coupon_no, for_update);
  proxy->PutHandler(h);
  return r;
}

