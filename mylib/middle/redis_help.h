#pragma once

#include <string>
#include <memory>

#include <stdint.h>

#include "hiredis/hiredis.h"
#include "util/pool.h"

namespace miku {
class RedisHandler {
 public:
  struct RedisHandlerConf {
    std::string host;
    uint32_t port;
    std::string auth;
  };
  using Conf = RedisHandlerConf;

  class ResultHelp {
   public:
    explicit ResultHelp(redisReply *);
    ~ResultHelp();
    redisReply *Reply() const;
    bool Ok() const;

   private:
    redisReply *reply_;
  };

  RedisHandler(const RedisHandlerConf &conf);
  ~RedisHandler();
//  std::shared_ptr<ResultHelp> Command(const char *fmt, ...) __attribute__ (( format (printf, 2, 3)));
  template <typename ... Args>
  std::shared_ptr<ResultHelp> Command(Args && ... args) {
    if (ctx_ == nullptr) {
      return std::make_shared<ResultHelp>(nullptr);
    }

    auto *reply = reinterpret_cast<redisReply *>(
        redisCommand(ctx_, std::forward<Args>(args)...));
    return std::make_shared<ResultHelp>(reply);
  }

  static RedisHandler *Create(const Conf &);
  bool Alive() const;

 private:
  const RedisHandlerConf &conf_;
  redisContext *ctx_;

  void DoConnect();
};


class RedisProxy {
 public:
  RedisProxy(const RedisHandler::RedisHandlerConf &conf);
  ~RedisProxy() = default;

  template <typename ... Args>
  std::shared_ptr<RedisHandler::ResultHelp> Command(Args && ... args) {
    auto redis = pool_.Get();
    if (redis == nullptr) {
      return std::make_shared<RedisHandler::ResultHelp>(nullptr);
    }

    auto ret = redis->Command(std::forward<Args>(args) ...);
    return ret;
  }
  RedisProxy *operator->();

 private:
  miku::Pool<RedisHandler> pool_;
};

}  // namespace miku
