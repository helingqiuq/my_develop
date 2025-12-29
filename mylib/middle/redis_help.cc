#include "redis_help.h"

#include <iostream>

#include "util/log.h"

namespace miku {

RedisHandler::ResultHelp::ResultHelp(redisReply *reply)
    : reply_(reply) {
  // nothing
}

RedisHandler::ResultHelp::~ResultHelp() {
  if (reply_ != nullptr) {
    freeReplyObject(reply_);
  }
}

redisReply *
RedisHandler::ResultHelp::Reply() const {
  return reply_;
}

bool
RedisHandler::ResultHelp::Ok() const {
  return reply_ != nullptr;
}

RedisHandler::RedisHandler(const RedisHandlerConf &conf)
    : conf_(conf) {
  DoConnect();
}

RedisHandler::~RedisHandler() {
  if (ctx_ != nullptr) {
    redisFree(ctx_);
  }
}

void
RedisHandler::DoConnect() {
  if (!conf_.host.empty() && conf_.port != 0) {
    ctx_ = redisConnect(conf_.host.c_str(), conf_.port);
    if (ctx_ == nullptr) {
      LogWarn("redis 连接错误");
      return;
    }

    if (!conf_.auth.empty()) {
      redisReply *auth_reply = (redisReply *)redisCommand(
          ctx_, "AUTH %s", conf_.auth.c_str());
      if (auth_reply == nullptr || auth_reply->type == REDIS_REPLY_ERROR) {
        LogWarn("认证失败: " << (auth_reply ? auth_reply->str : "未知错误"));
        if (auth_reply != nullptr) {
          freeReplyObject(auth_reply);
        }

        redisFree(ctx_);
        ctx_ = nullptr;
        return;
      }

      freeReplyObject(auth_reply);
    }
  }
}

RedisHandler *
RedisHandler::Create(const Conf &conf) {
  return new RedisHandler(conf);
}

bool
RedisHandler::Alive() const {
  return ctx_ != nullptr;
}

RedisProxy::RedisProxy(const RedisHandler::RedisHandlerConf &conf)
  : pool_(conf) {
}

RedisProxy *
RedisProxy::operator->() {
  return this;
}

}  // namespace miku
