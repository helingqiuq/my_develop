#pragma once

#include <string>

#include <stdint.h>
#include <time.h>

#include "json/json.h"

struct UserRecord {
  uint64_t     user_id;         // 用户id
  uint32_t    type;             // 操作: 0创建 1冻结 2核销 3异常
  Json::Value attr;             // 操作属性
  uint64_t    operator_id;      // 操作员id
  time_t      created;          // 创建时间
  std::string context;          // 备注
  Json::Value extension;        // 扩展字段
  std::string signature;        // 数据签名


  void Sign(const std::string &sign_key);
  bool CheckSign(const std::string &sign_key) const;
  std::string MakeInsertSql(const std::string &tname) const;
  std::string DebugString() const;

  static std::string MakeSign(const UserRecord &c,
                              const std::string &sign_key);
};

