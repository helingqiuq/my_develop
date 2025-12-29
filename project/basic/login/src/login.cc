#include "login.h"

#include <sstream>

#include "encrypt_help/hash.h"
#include "util/util.h"
#include "util/log.h"
#include "middle/mysql_help.h"
#include "proto/login.grpc.pb.h"

const char *Login::select_column =
               " `id`"
               ",`appid`"
               ",`salt`"
               ",`type`"
               ",`auth_key`"
               ",`status`"
               ",`attr`"
               ",`param`"
               ",`user_id`"
               ",UNIX_TIMESTAMP(`created`)"
               ",UNIX_TIMESTAMP(`updated`)"
               ",`context`"
               ",`extension`"
               ",`signature`";

std::string
Login::MakeSign(const Login &l, const std::string &sign_key) {
  std::stringstream ss;
  ss << l.appid
     << l.salt
     << l.type
     << l.auth_key
     << l.status
     << miku::json_to_string(l.attr)
     << miku::json_to_string(l.param)
     << l.user_id
     << l.created
     << l.updated;

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
Login::Sign(const std::string &sign_key) {
  std::string s = MakeSign(*this, sign_key);
  this->signature = s;
}

bool
Login::CheckSign(const std::string &sign_key) const {
  std::string s = MakeSign(*this, sign_key);
  return s == this->signature;
}


std::string
Login::MakeInsertSql(const std::string &tname) const {
  std::stringstream ss_column;
  std::stringstream ss_value;
  ss_column << "`appid`";
  ss_value << miku::mysql_help_quote_string(appid);
  ss_column << ",`salt`";
  ss_value << "," << miku::mysql_help_quote_string(salt);
  ss_column << ",`type`";
  ss_value << "," << type;
  ss_column << ",`auth_key`";
  ss_value << "," << miku::mysql_help_quote_string(auth_key);
  ss_column << ",`status`";
  ss_value << "," << status;
  ss_column << ",`attr`";
  ss_value << "," << miku::mysql_help_quote_string(miku::json_to_string(attr));
  ss_column << ",`param`";
  ss_value << "," << miku::mysql_help_quote_string(miku::json_to_string(param));
  ss_column << ",`user_id`";
  ss_value << "," << user_id;
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
Login::MakeUpdateSql(const std::string &tname) const {
  std::stringstream ss_update;
  ss_update
    << "UPDATE `" << tname << "` SET"
    << " `status`=" << status
    << ",`attr`=" << miku::mysql_help_quote_string(miku::json_to_string(attr))
    << ",`user_id`=" << user_id
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
Login::MakeAbnormalSql(const std::string &tname) const {
  std::stringstream ss_abnormal;
  ss_abnormal
    << "UPDATE `" << tname << "` SET"
    << " `status`=" << miku::login::LoginStatus::LS_ABNORMAL
    << " WHERE `id`=" << id
    << " AND `auth_key`=" << miku::mysql_help_quote_string(auth_key)
    << " AND `appid`=" << miku::mysql_help_quote_string(appid);

  return ss_abnormal.str();
}

std::string
Login::DebugString() const {
  std::stringstream ss;
  ss << "id = " << id << std::endl
     << "appid = " << appid << std::endl
     << "salt = " << salt << std::endl
     << "type = " << type << std::endl
     << "auth_key = " << auth_key << std::endl
     << "status = " << status << std::endl
     << "attr = " << miku::json_to_string(attr) << std::endl
     << "param = " << miku::json_to_string(param) << std::endl
     << "user_id = " << user_id << std::endl
     << "created = " << created << std::endl
     << "updated = " << updated << std::endl
     << "context = " << context << std::endl
     << "extension = " << miku::json_to_string(extension) << std::endl
     << "signature = " << signature;
  return ss.str();
}

bool
Login::FromMysqlReuslt(MYSQL_ROW row) {
  if (!row) {
    return false;
  }

  this->id = strtoull(row[0], nullptr, 10);
  this->appid = row[1];
  this->salt = row[2];
  this->type = atoi(row[3]);
  this->auth_key = row[4];
  this->status = atoi(row[5]);
  auto jattr = miku::json_from_string(row[6]);
  this->attr = jattr ? std::move(*jattr) : Json::objectValue;
  auto jparam = miku::json_from_string(row[7]);
  this->param = jparam ? std::move(*jparam) : Json::objectValue;
  this->user_id = strtoull(row[8], nullptr, 10);
  this->created = strtoull(row[9], nullptr, 10);
  this->updated = strtoull(row[10], nullptr, 10);
  this->context = row[11];
  auto jextension = miku::json_from_string(row[12]);
  this->extension = jextension ? std::move(*jextension) : Json::objectValue;
  this->signature = row[13];

  return true;
}

std::tuple<int32_t, std::optional<Login>>
Login::SelectOne(miku::MysqlHandler *h,
                const std::string &tname,
                const uint64_t &id,
                const std::string &appid,
                const std::string &auth_key,
                bool for_update) {
  if (id == 0 && auth_key.empty()) {
    LogWarn("id and auth_key must set one.");
    return {miku::login::ErrNo::E_ARGS, std::nullopt};
  }

  std::stringstream ss_select;
  ss_select << "SELECT " << select_column
            << " FROM " << tname
            << " WHERE 1=1";
  if (id != 0) {
    ss_select << " AND `id`=" << id;
  }
  if (!auth_key.empty()) {
    ss_select << " AND `auth_key`=" << miku::mysql_help_quote_string(auth_key);
  }

  // appid允许为空，这里必需写上
  ss_select << " AND `appid`=" << miku::mysql_help_quote_string(appid);

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

  Login l;
  l.FromMysqlReuslt(row);
  return {0, l};
}

std::tuple<int32_t, std::optional<Login>>
Login::SelectOne(std::shared_ptr<miku::MysqlProxy> &proxy,
                const std::string &tname,
                const uint64_t &id,
                const std::string &appid,
                const std::string &auth_key,
                bool for_update) {
  auto h = proxy->GetHandler();
  auto r = SelectOne(h.get(), tname, id, appid, auth_key);
  proxy->PutHandler(h);
  return r;
}

std::map<std::string, LoginAttrKeyConfig>
LoginAttrKeyConfig::allow_valid_key = {
  {key_auth, {.enc_type = ENC_TYPE_HASH, .multiple = false}},
};

bool
LoginAttrKeyConfig::is_valid_key(const std::string &k) {
  return allow_valid_key.find(k) != allow_valid_key.end();
}

const
LoginAttrKeyConfig *LoginAttrKeyConfig::get_key_config(const std::string &k) {
  auto it = allow_valid_key.find(k);
  return it == allow_valid_key.end() ? nullptr : &it->second;
}


