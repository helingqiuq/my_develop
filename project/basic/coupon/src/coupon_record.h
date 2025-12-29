#pragma once

#include <string>

#include <stdint.h>
#include <time.h>

#include "json/json.h"

struct CouponRecord {
  std::string coupon_no;        // 券码
  uint32_t    type;             // 操作: 0创建 1启用 2核销 3作废 4过期
  uint32_t    old_status;       // 原状态
  uint32_t    new_status;       // 新状态
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

  static std::string MakeSign(const CouponRecord &c,
                              const std::string &sign_key);
};

