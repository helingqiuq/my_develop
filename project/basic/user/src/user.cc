#include "user.h"

#include <sstream>

#include "encrypt_help/hash.h"
#include "util/util.h"
#include "util/log.h"
#include "middle/mysql_help.h"
#include "proto/user.grpc.pb.h"

const char *User::select_column =
               " `id`"
               ",`user_id`"
               ",`salt`"
               ",`src_id`"
               ",`status`"
               ",`type`"
               ",`param`"
               ",`attr`"
               ",UNIX_TIMESTAMP(`created`)"
               ",UNIX_TIMESTAMP(`updated`)"
               ",`context`"
               ",`extension`"
               ",`signature`";

std::string
User::MakeSign(const User &c, const std::string &sign_key) {
  std::stringstream ss;
  ss << c.user_id
     << c.salt
     << c.src_id
     << c.status
     << c.type
     << miku::json_to_string(c.param)
     << miku::json_to_string(c.attr)
     << c.created
     << c.updated;

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
User::Sign(const std::string &sign_key) {
  std::string s = MakeSign(*this, sign_key);
  this->signature = s;
}

bool
User::CheckSign(const std::string &sign_key) const {
  std::string s = MakeSign(*this, sign_key);
  return s == this->signature;
}


std::string
User::MakeInsertSql(const std::string &tname) const {
  std::stringstream ss_column;
  std::stringstream ss_value;
  ss_column << "`user_id`";
  ss_value << user_id;
  ss_column << ",`salt`";
  ss_value << "," << miku::mysql_help_quote_string(salt);
  ss_column << ",`src_id`";
  ss_value << "," << src_id;
  ss_column << ",`status`";
  ss_value << "," << status;
  ss_column << ",`type`";
  ss_value << "," << type;
  ss_column << ",`param`";
  ss_value << "," << miku::mysql_help_quote_string(miku::json_to_string(param));
  ss_column << ",`attr`";
  ss_value << "," << miku::mysql_help_quote_string(miku::json_to_string(attr));
  ss_column << ",`created`";
  ss_value << ",FROM_UNIXTIME(" << created << ")";
  ss_column << ",`updated`";
  ss_value << ",FROM_UNIXTIME(" << updated << ")";
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
User::MakeUpdateSql(const std::string &tname) const {
  std::stringstream ss_update;
  ss_update
    << "UPDATE `" << tname << "` SET"
    << " `status`=" << status
    << ",`type`=" << type
    << ",`param`=" << miku::mysql_help_quote_string(miku::json_to_string(param))
    << ",`attr`=" << miku::mysql_help_quote_string(miku::json_to_string(attr))
    << ",`updated`=FROM_UNIXTIME(" << updated << ")"
    << ",`context`=" << miku::mysql_help_quote_string(context)
    << ",`extension`=" << miku::mysql_help_quote_string(
                            miku::json_to_string(extension))
    << ",`signature`=" << miku::mysql_help_quote_string(signature)
    << " WHERE `id`=" << id
    << " AND `user_id`=" << user_id;

  return ss_update.str();
}

std::string
User::MakeAbnormalSql(const std::string &tname) const {
  std::stringstream ss_abnormal;
  ss_abnormal
    << "UPDATE `" << tname << "` SET"
    << " `status`=" << miku::user::UserStatus::US_ABNORMAL
    << " WHERE `id`=" << id
    << " AND `user_id`=" << user_id;

  return ss_abnormal.str();
}

std::optional<std::vector<User>>
User::Select(miku::MysqlHandler *h,
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

  std::vector<User> dv;
  auto *mysql_reply = mysql_result_help->Reply();
  MYSQL_ROW row;
  while ((row = mysql_fetch_row(mysql_reply))) {
    User c;
    c.FromMysqlReuslt(row);
    dv.push_back(std::move(c));
  }

  return dv;
}

std::optional<std::vector<User>>
User::Select(std::shared_ptr<miku::MysqlProxy> &proxy,
               const std::string &tname,
               const std::vector<std::string> &and_cond,
               const std::vector<std::string> &or_cond,
               const int32_t &page_idx,
               const int32_t &page_size) {
  auto h = proxy->GetHandler();
  auto r = Select(h.get(), tname, and_cond, or_cond, page_idx, page_size);
  proxy->PutHandler(h);
  return r;
}


std::string
User::DebugString() const {
  std::stringstream ss;
  ss << "id = " << id << std::endl
     << "user_id = " << user_id << std::endl
     << "salt = " << salt << std::endl
     << "src_id = " << src_id << std::endl
     << "status = " << status << std::endl
     << "type = " << type << std::endl
     << "param = " << miku::json_to_string(param) << std::endl
     << "attr = " << miku::json_to_string(attr) << std::endl
     << "created = " << created << std::endl
     << "updated = " << updated << std::endl
     << "context = " << context << std::endl
     << "extension = " << miku::json_to_string(extension) << std::endl
     << "signature = " << signature;
  return ss.str();
}

bool
User::FromMysqlReuslt(MYSQL_ROW row) {
  if (!row) {
    return false;
  }

  this->id = strtoull(row[0], nullptr, 10);
  this->user_id = strtoull(row[1], nullptr, 10);
  this->salt = row[2];
  this->src_id = strtoull(row[3], nullptr, 10);
  this->status = atoi(row[4]);
  this->type = atoi(row[5]);
  auto jparam = miku::json_from_string(row[6]);
  this->param = jparam ? std::move(*jparam) : Json::objectValue;
  auto jattr = miku::json_from_string(row[7]);
  this->attr = jattr ? std::move(*jattr) : Json::objectValue;
  this->created = strtoull(row[8], nullptr, 10);
  this->updated = strtoull(row[9], nullptr, 10);
  this->context = row[10];
  auto jextension = miku::json_from_string(row[11]);
  this->extension = jextension ? std::move(*jextension) : Json::objectValue;
  this->signature = row[12];

  return true;
}

std::tuple<int32_t, std::optional<User>>
User::SelectOne(miku::MysqlHandler *h,
                const std::string &tname,
                const uint64_t &id,
                const uint64_t &user_id,
                bool for_update) {
  if (id == 0 && user_id == 0) {
    LogWarn("id and user_id must set one.");
    return {miku::user::ErrNo::E_ARGS, std::nullopt};
  }

  std::stringstream ss_select;
  ss_select << "SELECT " << select_column
            << " FROM " << tname
            << " WHERE 1=1";
  if (id != 0) {
    ss_select << " AND `id`=" << id;
  }
  if (user_id != 0) {
    ss_select << " AND `user_id`=" << user_id;
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

  auto *mysql_reply = mysql_result_help->Reply();
  MYSQL_ROW row = mysql_fetch_row(mysql_reply);
  if (!row) {
    return {0, std::nullopt};
  }

  User c;
  c.FromMysqlReuslt(row);
  return {0, c};
}

std::tuple<int32_t, std::optional<User>>
User::SelectOne(std::shared_ptr<miku::MysqlProxy> &proxy,
                const std::string &tname,
                const uint64_t &id,
                const uint64_t &user_id,
                bool for_update) {
  auto h = proxy->GetHandler();
  auto r = SelectOne(h.get(), tname, id, user_id, for_update);
  proxy->PutHandler(h);
  return r;
}

std::map<std::string, UserAttrKeyConfig> UserAttrKeyConfig::allow_valid_key = {
  {"phonenum", {.encrypt = true, .belong_to = ATTR, .multiple = true}},
  {"idcard", {.encrypt = true, .belong_to = ATTR, .multiple = true}},
  {"email", {.encrypt = true, .belong_to = ATTR, .multiple = true}},
  {"address", {.encrypt = true, .belong_to = ATTR, .multiple = true}},
  {"position", {.encrypt = false, .belong_to = PARAM, .multiple = false}},
};

bool
UserAttrKeyConfig::is_valid_key(const std::string &k) {
  return allow_valid_key.find(k) != allow_valid_key.end();
}

const
UserAttrKeyConfig *UserAttrKeyConfig::get_key_config(const std::string &k) {
  auto it = allow_valid_key.find(k);
  return it == allow_valid_key.end() ? nullptr : &it->second;
}


