#include "coupon_record.h"

#include <sstream>

#include "util/log.h"
#include "util/util.h"
#include "middle/mysql_help.h"
#include "encrypt_help/hash.h"

std::string
CouponRecord::MakeSign(const CouponRecord &c, const std::string &sign_key) {
  std::stringstream ss;
  ss << c.coupon_no
     << c.type
     << c.old_status
     << c.new_status
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
CouponRecord::Sign(const std::string &sign_key) {
  std::string s = MakeSign(*this, sign_key);
  this->signature = s;
}

bool
CouponRecord::CheckSign(const std::string &sign_key) const {
  std::string s = MakeSign(*this, sign_key);
  return s == this->signature;
}

std::string
CouponRecord::MakeInsertSql(const std::string &tname) const {
  std::stringstream ss_column;
  std::stringstream ss_value;
  ss_column << "`coupon_no`";
  ss_value << miku::mysql_help_quote_string(coupon_no);
  ss_column << ",`type`";
  ss_value << "," << type;
  ss_column << ",`old_status`";
  ss_value << "," << old_status;
  ss_column << ",`new_status`";
  ss_value << "," << new_status;
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
CouponRecord::DebugString() const {
  std::stringstream ss;
  ss << "coupon_no = " << coupon_no << std::endl
     << "type = " << type << std::endl
     << "old_status = " << old_status << std::endl
     << "new_status = " << new_status << std::endl
     << "attr = " << miku::json_to_string(attr) << std::endl
     << "operator_id = " << operator_id << std::endl
     << "created = " << created << std::endl
     << "context = " << context << std::endl
     << "extension = " << miku::json_to_string(extension) << std::endl
     << "signature = " << signature;
  return ss.str();
}
