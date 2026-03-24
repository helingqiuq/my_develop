#pragma once

#include <functional>
#include <string>

#include <stdint.h>

#include "curl/curl.h"

namespace miku {

class CurlHelp {
 public:
  static void Initialize();

  using DataCallback = std::function<void(const char*, size_t)>;

  CurlHelp();
  ~CurlHelp();

  void SetReadCallback(const DataCallback &callback);
  void SetWriteCallback(const DataCallback &callback);

  void AddHeader(const std::string &h);  // "Content-Type: application/json"
  void SetUrl(const std::string &url);  // 设置远端地址
                                        //
  void SetKeepAlive(bool b = true);  // 长连接
  void SetKeepIdle(uint64_t idle = 60);  // 空闲多久之后开始发送第一个 TCP Keep-Alive 探测包。单位为秒
  void SetKeepIntvl(uint64_t intvl = 20);  // 设置在发送后续探测包之间的间隔时间。单位为秒
  void SetTimeout(uint64_t tt = 10);  // 设置超时时间。单位秒
  void SetTimeoutMs(uint64_t ttms = 1000);  // 设置超时时间。单位毫秒
  void SetVerbose(bool b = true);  // 调试信息
  void SetForbidReuse(bool b = true);  // 连接复用
  void SetProxy(const std::string &proxy);  // 设置代理. "http://proxy.example.com:8080"


  bool Get();  // 发起get请求
  bool Post(const std::string &d);  // 发起post请求


 private:
  static size_t write_data(void *d, size_t s, size_t n, void *pd);
  static size_t read_data(void *d, size_t s, size_t n, void *pd);

  CURL *curl_;
  struct curl_slist *headers_;

  DataCallback rd_callback_;
  DataCallback wr_callback_;
};


}  // namespace miku
