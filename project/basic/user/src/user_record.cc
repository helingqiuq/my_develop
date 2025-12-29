#include "user_record.h"

#include <sstream>

#include "util/log.h"
#include "util/util.h"
#include "middle/mysql_help.h"
#include "encrypt_help/hash.h"

std::string
UserRecord::MakeSign(const UserRecord &c, const std::string &sign_key) {
  std::stringstream ss;
  ss << c.user_id
     << c.type
     << miku::json_to_string(c.attr)
     << c.operator_id
     << c.created;

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
UserRecord::Sign(const std::string &sign_key) {
  std::string s = MakeSign(*this, sign_key);
  this->signature = s;
}

bool
UserRecord::CheckSign(const std::string &sign_key) const {
  std::string s = MakeSign(*this, sign_key);
  return s == this->signature;
}

std::string
UserRecord::MakeInsertSql(const std::string &tname) const {
  std::stringstream ss_column;
  std::stringstream ss_value;
  ss_column << "`user_id`";
  ss_value  << user_id;
  ss_column << ",`type`";
  ss_value << "," << type;
  ss_column << ",`attr`";
  ss_value << "," << miku::mysql_help_quote_string(miku::json_to_string(attr));
  ss_column << ",`operator_id`";
  ss_value << "," << operator_id;
  ss_column << ",`created`";
  ss_value << ",FROM_UNIXTIME(" << created << ")";
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
UserRecord::DebugString() const {
  std::stringstream ss;
  ss << "user_id = " << user_id << std::endl
     << "type = " << type << std::endl
     << "attr = " << miku::json_to_string(attr) << std::endl
     << "operator_id = " << operator_id << std::endl
     << "created = " << created << std::endl
     << "context = " << context << std::endl
     << "extension = " << miku::json_to_string(extension) << std::endl
     << "signature = " << signature;
  return ss.str();
}
