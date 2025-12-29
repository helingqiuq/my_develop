#pragma once

#include "util/lock_helper.h"
#include <thread>

namespace miku {

template<typename C, typename K, typename V>
class ConfigManage {
 private:
  using UpdateProc = std::function<bool(std::map<K, V> *m,
                                        C *c,
                                        void *user_data)>;
  miku::LockHelper rwlock_;
  std::map<K, V> *current_;
  std::map<K, V> *buf_[2];  // 两个buf，做update时转换使用，延迟释放
  uint32_t count_;  // 每更新一次加1，主要用户记录使用哪个buf

  // 自动更新时的参数
  miku::LockHelper update_lock_;  // 避免更新冲突
  std::thread update_thread_;  // 自动更新线程
  bool update_exit_;  // 退出标志
  uint32_t update_span_;  // 每次更新的时间间隔（秒）
  time_t next_update_timestamp_;  // 下一次更新的时间戳，只有 update_span_不为0时有用
  UpdateProc update_proc_;  // 更新的调用过程
  void *user_data_;  // 更新的用户数据
  C *c_;

  ConfigManage() {
    current_ = nullptr;
    memset(buf_, 0, sizeof(buf_));
    count_ = 0;
    update_exit_ = false;
    update_span_ = 0;
    next_update_timestamp_ = 0;
    update_proc_ = nullptr;
    user_data_ = nullptr;
  }

  ~ConfigManage() {
    for (uint32_t i = 0; i < sizeof(buf_)/sizeof(buf_[0]); i++) {
      if (buf_[i] != nullptr) delete buf_[i];
    }

    update_exit_ = true;
    if (update_thread_.joinable()) {
      update_thread_.join();
    }
  }

 public:
  static ConfigManage *get() {
    static ConfigManage s;
    return &s;
  }

  const V *GetValue(const K &k) {
    auto l = rwlock_.RdLock();
    if (current_ == nullptr) {
      return nullptr;
    }

    auto it = current_->find(k);
    if (it == current_->end()) {
      return nullptr;
    }

    return &it->second;
  }

  // 用于动态更新
  bool Update(
      UpdateProc update_proc,
      C *c,
      void *user_data) {
    auto *pnew_data = new std::map<K, V>();
    bool ret = update_proc(pnew_data, c, user_data);
    if (!ret) {
      // 恢复原来的状态
      delete pnew_data;
      return false;
    } else {
      uint16_t new_index = ++count_ % (sizeof(buf_) / sizeof(buf_[0]));
      if (buf_[new_index] != nullptr) delete buf_[new_index];
      buf_[new_index] = pnew_data;

      auto l = rwlock_.WrLock();
      current_ = buf_[new_index];

      return true;
    }
  }

  // 用于第一次初始化
  int32_t Init(UpdateProc init_proc,
               UpdateProc update_proc,
               uint32_t update_span,
               C *c,
               void *user_data) {
    auto l = rwlock_.WrLock();
    if (current_ != nullptr) {
      return 1;
    }

    if (init_proc == nullptr) {
      return -1;
    }

    count_ = 0;
    if (buf_[0] != nullptr) {
      delete buf_[0];
      buf_[0] = nullptr;
    }

    buf_[0] = new std::map<K, V>();
    bool ret = init_proc(buf_[0], c, user_data);
    if (!ret) {
      delete buf_[0];
      buf_[0] = nullptr;
      return -1;
    }

    current_ = buf_[0];

    if (update_span > 0 &&
        update_proc != nullptr &&
        !update_thread_.joinable()) {
      update_span_ = update_span;
      next_update_timestamp_ = time(nullptr) + update_span_;
      update_proc_ = update_proc;
      user_data_ = user_data;
      c_ = c;

      update_thread_ = std::thread(
          [](ConfigManage *cm, void *user_data) -> void {
            while (!cm->update_exit_) {
              if (time(nullptr) > cm->next_update_timestamp_) {
                int32_t ret;
                cm->update_lock_.try_lock_do(
                    [](ConfigManage *cm) -> int32_t {
                      return cm->Update(cm->update_proc_,
                                        cm->c_,
                                        cm->user_data_);}, &ret, cm);
                cm->next_update_timestamp_ = time(nullptr) + cm->update_span_;
              } else {
                std::this_thread::sleep_for(std::chrono::seconds(1));
              }
            }
            return;
          }, this, user_data);
    }

    return 0;
  }
};

}  // namespace miku
