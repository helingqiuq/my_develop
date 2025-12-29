#pragma once

#include <string>
#include <optional>
#include <vector>
#include <tuple>

#include <stdint.h>
#include <time.h>

#include "json/json.h"
#include "middle/mysql_help.h"

struct User {
  uint64_t    id;               // 在db中的id
  uint64_t    user_id;          // 用户唯一标识user_id
  std::string salt;             // 盐值
  uint32_t    src_id;           // 来源id
  uint32_t    status;           // 用户状态, 0正常 1冻结 2销户 3异常数据
  uint32_t    type;             // 用户类型 0普通用户
  Json::Value param;            // 用户属性相关的非敏感参数
  Json::Value attr;             // 用户个人数据，证件号，电话等敏感数据
  time_t      created;          // 创建时间
  time_t      updated;          // 最后更新时间
  std::string context;          // 备注
  Json::Value extension;        // 扩展字段
  std::string signature;        // 数据签名

  static const char *select_column;
  void Sign(const std::string &sign_key);
  bool CheckSign(const std::string &sign_key) const;
  std::string MakeInsertSql(const std::string &tname) const;
  // update 必需用id 和 券号
  std::string MakeUpdateSql(const std::string &tname) const;
  // Abnormal 必需用id 和 券号,只改一下状态
  std::string MakeAbnormalSql(const std::string &tname) const;
  std::string DebugString() const;

  // 此函数需要与 select_sql 配对使用
  bool FromMysqlReuslt(MYSQL_ROW row);

  static std::string MakeSign(const User &c, const std::string &sign_key);
  // where 1=1 [and and_cond1 and and_cond1 ... ] [and (or_cond1 or or_cond2 ...)]
  // 该函数的条件需要外部做好防注入
  static std::optional<std::vector<User>>
  Select(std::shared_ptr<miku::MysqlProxy> &proxy,
         const std::string &tname,
         const std::vector<std::string> &and_cond = {},
         const std::vector<std::string> &or_cond = {},
         const int32_t &page_idx = 0,
         const int32_t &page_size = 20);
  static std::optional<std::vector<User>>
  Select(miku::MysqlHandler *h,
         const std::string &tname,
         const std::vector<std::string> &and_cond = {},
         const std::vector<std::string> &or_cond = {},
         int32_t page_idx = 0,
         int32_t page_size = 20);

  static std::tuple<int32_t, std::optional<User>>
  SelectOne(miku::MysqlHandler *h,
            const std::string &tname,
            const uint64_t &id = 0,
            const uint64_t &user_id = 0,
            bool for_update = false);
  static std::tuple<int32_t, std::optional<User>>
  SelectOne(std::shared_ptr<miku::MysqlProxy> &proxy,
            const std::string &tname,
            const uint64_t &id = 0,
            const uint64_t &user_id = 0,
            bool for_update = false);

};

struct UserAttrKeyConfig {
  bool encrypt;
  enum BELONG_TO {
    ATTR = 0,
    PARAM
  } belong_to;
  bool multiple;

  static std::map<std::string, UserAttrKeyConfig> allow_valid_key;
  static bool is_valid_key(const std::string &k);
  static const UserAttrKeyConfig *get_key_config(const std::string &k);
};
