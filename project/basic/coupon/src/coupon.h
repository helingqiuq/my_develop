#pragma once

#include <string>
#include <optional>
#include <vector>
#include <tuple>

#include <stdint.h>
#include <time.h>

#include "json/json.h"
#include "middle/mysql_help.h"

struct Coupon {
  uint64_t    id;               // 在db中的id
  std::string coupon_no;        // 券码
  std::string activity_id;      // 券所属的活动id
  std::string activity_cycle;   // 券所属的活动id的周期
  uint32_t    type;             // 券类型: 0初始(无效值);1无门槛折扣;2满减;3无门槛打折;4带上限打折;5余额型
  uint32_t    status;           // 券状态
  Json::Value attr;             // 券属性，各种参数
  uint64_t    user_id;          // 券所属的user_id
  time_t      created;          // 创建时间
  time_t      updated;          // 最后更新时间
  time_t      started;          // 启用时间
  time_t      expired;          // 过期时间
  time_t      redemption;       // 核销时间
  time_t      cancel;           // 作废时间
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

  static std::string MakeSign(const Coupon &c, const std::string &sign_key);
  // where 1=1 [and and_cond1 and and_cond1 ... ] [and (or_cond1 or or_cond2 ...)]
  // 该函数的条件需要外部做好防注入
  static std::optional<std::vector<Coupon>>
  Select(std::shared_ptr<miku::MysqlProxy> &proxy,
         const std::string &tname,
         const std::vector<std::string> &and_cond = {},
         const std::vector<std::string> &or_cond = {},
         int32_t page_idx = 0,
         int32_t page_size = 20);
  static std::optional<std::vector<Coupon>>
  Select(miku::MysqlHandler *h,
         const std::string &tname,
         const std::vector<std::string> &and_cond = {},
         const std::vector<std::string> &or_cond = {},
         int32_t page_idx = 0,
         int32_t page_size = 20);

  static std::tuple<int32_t, std::optional<Coupon>>
  SelectOne(miku::MysqlHandler *h,
            const std::string &tname,
            uint64_t id = 0,
            const std::string &coupon_no = "",
            bool for_update = false);
  static std::tuple<int32_t, std::optional<Coupon>>
  SelectOne(std::shared_ptr<miku::MysqlProxy> &proxy,
            const std::string &tname,
            uint64_t id = 0,
            const std::string &coupon_no = "",
            bool for_update = false);
};
