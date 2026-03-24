#pragma once

#include <map>
#include <string>
#include <memory>
#include <atomic>
#include <tuple>

#include <stdint.h>

#include "lock_helper.h"

namespace miku {

class Statistics {
 public:
  // name  // 监控控制台名
  // stat_name // 监控指标名
  // stat_attr // 监控属性名
  // report(uint64_t v = 1)  // 上报数据，两个层次都支持
  // operator[]
  explicit Statistics(const std::string &name = "");
  ~Statistics() = default;

  struct AttrValue {
    enum ValueType {
      RAW = 0,
      AVE,
    };
    // 这个不需要lock
    std::atomic_uint64_t value_;
    std::atomic_uint64_t cnt_;
    ValueType vt_;

    AttrValue(ValueType vt = RAW);
    ~AttrValue() = default;

    void Add(uint64_t v = 1);
    void Set(uint64_t v);
    uint64_t Value() const;
    uint64_t RawValue() const;
    uint64_t Count() const;
    std::tuple<uint64_t, uint64_t> Reset();
  };

  struct StatAttrInfo {
    miku::LockHelper *plock_;
    std::string name_;
    std::map<std::string, std::shared_ptr<AttrValue>> attrs_;

    explicit StatAttrInfo(miku::LockHelper *l, const std::string &name = "");
    ~StatAttrInfo() = default;
    std::shared_ptr<AttrValue> TryGetAttrValue(
        const std::string &attr_name,
        bool create = false,
        AttrValue::ValueType vt = AttrValue::RAW);

    void Add(const std::string &attr_name,
             uint64_t v = 1,
             AttrValue::ValueType vt = AttrValue::RAW);  // 如果不存在，则创建
    void Set(const std::string &attr_name,
             uint64_t v,
             AttrValue::ValueType vt = AttrValue::RAW);  // 如果不存在，则创建
    std::shared_ptr<AttrValue> Register(
        const std::string &attr_name,  // 存在则不会覆盖
        AttrValue::ValueType vt = AttrValue::RAW);
    uint64_t Value(const std::string &attr_name) const;  // 未查得返回0
    uint64_t Count(const std::string &attr_name) const;  // 未查得返回0
    std::shared_ptr<AttrValue> Attr(const std::string &attr_name,
                                    bool create = false,  // 没有则注册
                                    AttrValue::ValueType vt = AttrValue::RAW);  // 值计算方式
    std::map<std::string, std::tuple<uint64_t, uint64_t>> Reset(bool l = true);
    std::tuple<uint64_t, uint64_t> Reset(const std::string &attr_name);
  };

  std::shared_ptr<StatAttrInfo> TryGetStat(const std::string &stat_name,
                                           bool create = false);

  void SetName(const std::string &name);
  const std::string &Name() const;
  void Add(const std::string &stat_name,
           const std::string &attr_name,
           uint64_t v = 1,
           AttrValue::ValueType vt = AttrValue::RAW);  // 如果不存在，则创建
  void Set(const std::string &stat_name,
           const std::string &attr_name,
           uint64_t v,
           AttrValue::ValueType vt = AttrValue::RAW);  // 如果不存在，则创建
  std::shared_ptr<StatAttrInfo> Register(const std::string &stat_name);  // 存在则不会覆盖
  std::shared_ptr<AttrValue> Register(const std::string &stat_name,
                                      const std::string &attr_name,  // 存在则不会覆盖
                                      AttrValue::ValueType vt = AttrValue::RAW);
  uint64_t Value(const std::string &stat_name,
                 const std::string &attr_name) const;  // 未查得返回0
  uint64_t Count(const std::string &stat_name,
                 const std::string &attr_name) const;  // 未查得返回0
  std::shared_ptr<StatAttrInfo> Stat(const std::string &stat_name,
                                     bool create = false);  // 没有则注册
  std::map<std::string,
           std::map<std::string,
                    std::tuple<uint64_t, uint64_t>>> Reset();
  std::map<std::string,
           std::tuple<uint64_t, uint64_t>> Reset(const std::string &stat_name);
  std::tuple<uint64_t, uint64_t> Reset(const std::string &stat_name,
                                       const std::string &attr_name);

 private:
  std::string name_;
  std::map<std::string, std::shared_ptr<StatAttrInfo>> stats_;
  miku::LockHelper lock_;
};


}  // namespace miku
