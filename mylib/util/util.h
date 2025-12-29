#pragma once

#include <pthread.h>
#include <time.h>
#include <netinet/in.h>

#include <string>
#include <iostream>
#include <set>
#include <map>
#include <sstream>
#include <memory>
#include <shared_mutex>
#include <mutex>
#include <thread>
#include <functional>
#include <chrono>
#include <tuple>
#include <optional>
#include <type_traits>
#include <random>
#include <algorithm>

#include "json/json.h"

namespace miku {

// 唯一id
std::string gen_id();
std::vector<std::string> split(const std::string &s,
                               const char &split_char,
                               const char &escape_char = '\0');  // '\0'默认值为无需处理转义

std::string trim(const std::string &s, const char &c = ' ');

int32_t set_non_blocking_mode(int32_t fd);
int32_t set_close_on_exec_mode(int32_t fd);
int32_t get_local_ipaddr_raw(const char *peer_addr,

struct in_addr *pinaddr);
int32_t get_local_ipaddr_ui(const char *peer_addr, uint32_t *pui);

pid_t gettid();

// 获取本地IP
const char *local_ip4_str();

// 随机字符串
void make_random_string(char *pbuf, uint32_t n);
std::string make_random_string(uint32_t n = 16);
template <typename T>
T make_random_integral(const T &b, const T &e) {
  std::random_device rd;
  return  std::uniform_int_distribution<T>(b, e)(rd);
}
template <typename T>
void randomization(T &d) {
  std::random_device rd;
  std::default_random_engine generator(rd());
  std::shuffle(d.begin(), d.end(), generator);
}

std::tuple<bool, uint32_t> safe_write(int32_t fd, const char *d, uint64_t n);
std::tuple<bool, uint32_t> safe_read(int32_t fd, char *d, uint64_t n);

std::optional<std::string> get_module_path(pid_t pid = 0);  // 取pid的exe路径
std::optional<std::string> get_module_script(pid_t pid = 0);  // 取第一个参数
std::optional<std::string> format_full_path(const std::string &raw_path);
std::optional<std::string> get_file_md5(const std::string &fname);
std::optional<std::string> get_file_sha256(const std::string &fname);
std::tuple<uint32_t, std::string>
split_string(const char *s, const char split_word);
int32_t create_unix_lfd(const std::string &a);
int32_t create_tcp_lfd(const std::string &a, uint32_t port);
bool is_number(const std::string &s,
               bool allow_neg = false,   // 允许负数
               bool allow_dec = false);  // 允许小数

std::string json_to_string(const Json::Value &jv);
std::optional<Json::Value> json_from_string(const std::string &s);
std::optional<Json::Value> json_from_file(const std::string &f);
bool json_sarr_has_value(const Json::Value &ja, const std::string &s);
void json_sarr_remove_value(Json::Value *ja, const std::string &s);

std::tuple<bool, std::string, int32_t>
intstring_div(const std::string &s,
              const int32_t divisor);

std::tuple<uint32_t, uint64_t> varint_get(const char *ptr);
uint32_t varint_set(uint64_t v, char ptr[10]);

std::string cfg_get_string(const Json::Value &v,
                           const std::string &path,
                           const std::string &def);
int64_t cfg_get_integer(const Json::Value &v,
                        const std::string &path,
                        int64_t def);

template <typename T>
T cfg_get(const Json::Value &v, const std::string &path, const T &def) {
  if constexpr (std::is_same_v<T, std::string>) {
    return cfg_get_string(v, path, def);
  } else if constexpr (std::is_integral_v<T>) {
    return static_cast<T>(cfg_get_integer(v, path, def));
  } else {
    static_assert(std::false_type::value, "unknow type");
  }
}

template <typename T>
T cfg_get_must(const Json::Value &v,
                     const std::string &path,
                     const T &def) {
  T r = cfg_get(v, path, def);
  if constexpr (std::is_same_v<T, std::string>) {
    if (r.empty()) {
      std::cerr << "<" << path << "> not set" << std::endl;
      exit(1);
    }
  } else if constexpr (std::is_integral_v<T>) {
    if (r == 0) {
      std::cerr << "<" << path << "> not set" << std::endl;
      exit(1);
    }
  }
  return r;
}


extern decltype(cfg_get<int32_t>) *cfg_get_i;
extern decltype(cfg_get<uint32_t>) *cfg_get_ui;
extern decltype(cfg_get<int64_t>) *cfg_get_l;
extern decltype(cfg_get<uint64_t>) *cfg_get_ul;
extern decltype(cfg_get<std::string>) *cfg_get_s;
extern decltype(cfg_get_must<int32_t>) *cfg_get_ci;
extern decltype(cfg_get_must<uint32_t>) *cfg_get_cui;
extern decltype(cfg_get_must<int64_t>) *cfg_get_cl;
extern decltype(cfg_get_must<uint64_t>) *cfg_get_cul;
extern decltype(cfg_get_must<std::string>) *cfg_get_cs;



// default_type，当路径为相对路径时的路径选取。
// 0，从pwd进行相对路径补充
// 1，从module_path进行相对路径补充
// 其它，从pwd进行相对路径补充
std::optional<std::string>
get_absolute_path(const char *path_src, int default_type = 0);
std::string
str_replace(const std::string &raw,
            const std::string &src,
            const std::string &des);

template <uint32_t SC, uint32_t TC, typename T>
std::tuple<uint32_t, uint32_t>  // {库号, 表号}
get_dbroute(const T &t) {
  if constexpr (std::is_integral_v<T>) {
    return {(t / TC) % SC, t % TC};
  } else {
    auto hv = std::hash<T>{}(t);
    return {(hv / TC) % SC, hv % TC};
  }
}

// unix时间戳转 yyyy-mm-dd hh:MM:SS
std::string ts_to_dtstring(time_t t);
std::string ts_to_dtstring();

// unix时间戳转 hh:MM:SS
std::string ts_to_tstring(time_t t);
std::string ts_to_tstring();

// unix时间戳转 yyyy-mm-dd
std::string ts_to_dstring(time_t t);
std::string ts_to_dstring();

// unix时间戳转 yyyy
std::string ts_to_year(time_t t);
std::string ts_to_year();

// unix时间戳转去年 yyyy
std::string ts_to_last_year(time_t t);
std::string ts_to_last_year();

// 字符串转回时间戳
std::optional<time_t>
ts_from_string(const char *st, const char *fmt = "%Y-%m-%d %H:%M:%S");

std::string ts_to_string(time_t t, const char *fmt = "%Y-%m-%d %H:%M:%S");



}  // namespace miku


#define DECLARE_MEMBER_CHECK(n)                                     \
template <typename T>                                               \
struct CheckHas_##n {                                               \
  template<typename U>                                              \
  static auto check(int) -> decltype(std::declval<U>().n(),         \
                                     std::true_type());             \
  template<typename U>                                              \
  static auto check(...) -> decltype(std::false_type());            \
  static const bool value = std::is_same_v<decltype(check<T>(0)),   \
                                           std::true_type>;         \
};
