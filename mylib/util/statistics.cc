#include "statistics.h"

namespace miku {

// Statistics::AttrValue

Statistics::AttrValue::AttrValue(ValueType vt)
    : vt_(vt) {
}

void
Statistics::AttrValue::Add(uint64_t v) {
  this->value_ += v;
  this->cnt_++;
}

void
Statistics::AttrValue::Set(uint64_t v) {
  this->value_ = v;
  this->cnt_ = 1;
}

uint64_t
Statistics::AttrValue::Value() const {
  if (vt_ == AVE) {
    if (this->cnt_ == 0) {
      return 0;
    } else {
      return this->value_ / this->cnt_;
    }
  } else {
    return this->value_;
  }
}

uint64_t
Statistics::AttrValue::RawValue() const {
  return this->value_;
}

uint64_t
Statistics::AttrValue::Count() const {
  return this->cnt_;
}

std::tuple<uint64_t, uint64_t>
Statistics::AttrValue::Reset() {
  uint64_t old_value = this->Value();
  uint64_t old_cnt = this->Count();
  this->value_ = 0;
  this->cnt_ = 0;
  return {old_value, old_cnt};
}


// Statistics::StatAttrInfo

Statistics::StatAttrInfo::StatAttrInfo(miku::LockHelper *l,
                                       const std::string &name)
    : plock_(l)
    , name_(name) {
}

std::shared_ptr<Statistics::AttrValue>
Statistics::StatAttrInfo::TryGetAttrValue(const std::string &attr_name,
                                          bool create,
                                          AttrValue::ValueType vt) {
  auto pv = plock_->rdserialization(
      [] (const StatAttrInfo *pstat_attr_info,
          const std::string &name) -> std::shared_ptr<AttrValue> {
        auto it = pstat_attr_info->attrs_.find(name);
        if (it == pstat_attr_info->attrs_.end()) {
          return nullptr;
        }
        return it->second;
      }, this, std::cref(attr_name));
  if (pv != nullptr) {
    return pv;
  }

  if (!create) {
    return nullptr;
  }

  return plock_->serialization(
    [] (StatAttrInfo *pstat_attr_info,
        const std::string &name,
        AttrValue::ValueType vt) -> std::shared_ptr<AttrValue> {
      auto it = pstat_attr_info->attrs_.find(name);
      if (it == pstat_attr_info->attrs_.end()) {
        auto pattr_value = std::make_shared<AttrValue>(vt);
        pstat_attr_info->attrs_[name] = pattr_value;
        return pattr_value;
      } else {
        return it->second;
      }
    }, this, std::cref(attr_name), vt);
}

void
Statistics::StatAttrInfo::Add(const std::string &attr_name,
                              uint64_t v,
                              AttrValue::ValueType vt) {
  Attr(attr_name, true, vt)->Add(v);
}

void
Statistics::StatAttrInfo::Set(const std::string &attr_name,
                              uint64_t v,
                              AttrValue::ValueType vt) {
  Attr(attr_name, true, vt)->Set(v);
}

std::shared_ptr<Statistics::AttrValue>
Statistics::StatAttrInfo::Register(const std::string &attr_name,
                                   AttrValue::ValueType vt) {
  return TryGetAttrValue(attr_name, true, vt);
}

std::shared_ptr<Statistics::AttrValue>
Statistics::StatAttrInfo::Attr(const std::string &attr_name,
                               bool create,
                               AttrValue::ValueType vt) {
  return TryGetAttrValue(attr_name, create, vt);
}

uint64_t
Statistics::StatAttrInfo::Value(const std::string &attr_name) const {
  auto pv = const_cast<StatAttrInfo *>(this)->TryGetAttrValue(attr_name);
  return pv == nullptr ? 0 : pv->Value();
}

uint64_t
Statistics::StatAttrInfo::Count(const std::string &attr_name) const {
  auto pv = const_cast<StatAttrInfo *>(this)->TryGetAttrValue(attr_name);
  return pv == nullptr ? 0 : pv->Count();
}

std::map<std::string, std::tuple<uint64_t, uint64_t>>
Statistics::StatAttrInfo::Reset(bool l) {
  static auto reset_proc = [] (StatAttrInfo *pstat_attr_info)
        -> std::map<std::string, std::tuple<uint64_t, uint64_t>> {
    std::map<std::string, std::tuple<uint64_t, uint64_t>> ov;
    for (auto &[k, v] : pstat_attr_info->attrs_) {
      ov[k] = v->Reset();
    }
    return ov;
  };

  if (l) {
    return plock_->serialization(
      [] (StatAttrInfo *pstat_attr_info)
            -> std::map<std::string, std::tuple<uint64_t, uint64_t>> {
        return reset_proc(pstat_attr_info);
      }, this);
  } else {
    return reset_proc(this);
  }
}

std::tuple<uint64_t, uint64_t>
Statistics::StatAttrInfo::Reset(const std::string &attr_name) {
  return Attr(attr_name, true)->Reset();
}


//  =============== Statistics

Statistics::Statistics(const std::string &name)
    : name_(name) {
}

std::shared_ptr<Statistics::StatAttrInfo>
Statistics::TryGetStat(const std::string &stat_name, bool create) {
  auto pv = lock_.rdserialization(
      [] (const Statistics *pstat,
          const std::string &name) -> std::shared_ptr<StatAttrInfo> {
        auto it = pstat->stats_.find(name);
        if (it == pstat->stats_.end()) {
          return nullptr;
        }

        return it->second;
      }, this, std::cref(stat_name));

  if (pv != nullptr) {
    return pv;
  }

  if (!create) {
    return nullptr;
  }

  return lock_.serialization(
    [] (Statistics *pstat,
        const std::string &stat_name) -> std::shared_ptr<StatAttrInfo> {
      auto it = pstat->stats_.find(stat_name);
      if (it == pstat->stats_.end()) {
        auto pstat_attr = std::make_shared<StatAttrInfo>(
              &pstat->lock_, stat_name);
        pstat->stats_[stat_name] = pstat_attr;
        return pstat_attr;
      } else {
        return it->second;
      }
    }, this, std::cref(stat_name));
}

void
Statistics::SetName(const std::string &name) {
  name_ = name;
}

const std::string &
Statistics::Name() const {
  return name_;
}

void
Statistics::Add(const std::string &stat_name,
                const std::string &attr_name,
                uint64_t v,
                AttrValue::ValueType vt) {
  Stat(stat_name, true)->Add(attr_name, v, vt);
}

void
Statistics::Set(const std::string &stat_name,
                const std::string &attr_name,
                uint64_t v,
                AttrValue::ValueType vt) {
  Stat(stat_name, true)->Set(attr_name, v, vt);
}

std::shared_ptr<Statistics::StatAttrInfo>
Statistics::Register(const std::string &stat_name) {
  return TryGetStat(stat_name, true);
}

std::shared_ptr<Statistics::AttrValue>
Statistics::Register(const std::string &stat_name,
                     const std::string &attr_name,
                     AttrValue::ValueType vt) {
  return Stat(stat_name, true)->Register(attr_name, vt);
}

uint64_t
Statistics::Value(const std::string &stat_name,
                  const std::string &attr_name) const {
  auto pstat = const_cast<Statistics *>(this)->TryGetStat(stat_name);
  return pstat == nullptr ? 0 : pstat->Value(attr_name);
}

uint64_t
Statistics::Count(const std::string &stat_name,
                  const std::string &attr_name) const {
  auto pstat = const_cast<Statistics *>(this)->TryGetStat(stat_name);
  return pstat == nullptr ? 0 : pstat->Count(attr_name);
}

std::shared_ptr<Statistics::StatAttrInfo>
Statistics::Stat(const std::string &stat_name,
                 bool create) {
  return TryGetStat(stat_name, create);
}

std::map<std::string,
         std::map<std::string,
                  std::tuple<uint64_t, uint64_t>>>
Statistics::Reset() {
  return lock_.serialization(
      [] (Statistics *pstatistics) -> decltype(this->Reset()) {
    decltype(pstatistics->Reset()) ret;
    for (auto &[k, v] : pstatistics->stats_) {
      ret[k] = v->Reset(false);
    }
    return ret;
   }, this);
}

std::map<std::string, std::tuple<uint64_t, uint64_t>>
Statistics::Reset(const std::string &stat_name) {
  return Stat(stat_name, true)->Reset();
}

std::tuple<uint64_t, uint64_t>
Statistics::Reset(const std::string &stat_name,
                  const std::string &attr_name) {
  return Stat(stat_name, true)->Attr(attr_name, true)->Reset();
}



}
