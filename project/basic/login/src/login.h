#pragma once

#include <string>
#include <optional>
#include <vector>
#include <tuple>

#include <stdint.h>
#include <time.h>

#include "json/json.h"
#include "middle/mysql_help.h"

struct Login {
  uint64_t    id;               // 在db中的id
  std::string appid;            // 标记登录的app平台
  std::string salt;             // 盐值
  uint32_t    type;             // 登入类型 0普通(验证key) 1已授权(已通过三方登陆鉴权) ...
  std::string auth_key;         // 登陆验证的key值
  uint32_t    status;           // 账户状态，0正常 1冻结 2销户 3异常数据
  Json::Value attr;             // 其它一些登陆属性
  Json::Value param;            // 注册时的一些参数
  uint64_t    user_id;          // 登陆后绑定的用户唯一标识
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

  static std::string MakeSign(const Login &l, const std::string &sign_key);

  static std::tuple<int32_t, std::optional<Login>>
  SelectOne(miku::MysqlHandler *h,
            const std::string &tname,
            const uint64_t &id = 0,
            const std::string &appid = "",
            const std::string &auth_key = "",
            bool for_update = false);
  static std::tuple<int32_t, std::optional<Login>>
  SelectOne(std::shared_ptr<miku::MysqlProxy> &proxy,
            const std::string &tname,
            const uint64_t &id = 0,
            const std::string &appid = "",
            const std::string &auth_key = "",
            bool for_update = false);

};

struct LoginAttrKeyConfig {
  enum {
    ENC_TYPE_RAW = 0,   // 明文
    ENC_TYPE_ENC,       // 加密
    ENC_TYPE_HASH,      // hash
  } enc_type ;
  bool multiple;
  constexpr static const char *key_auth = "auth_secret";

  static std::map<std::string, LoginAttrKeyConfig> allow_valid_key;
  static bool is_valid_key(const std::string &k);
  static const LoginAttrKeyConfig *get_key_config(const std::string &k);
};
