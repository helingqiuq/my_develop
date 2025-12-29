#pragma once

#include <string>
#include <memory>
#include <vector>
#include <tuple>

#include <stdint.h>

#include "json/json.h"
#include "mysql/mysql.h"
#include "mysql/mysqld_error.h"
#include "util/pool.h"
#include "util/util.h"
#include "util/log.h"

namespace miku {

bool is_mysql_retry_errno(int32_t e);

class MysqlHandler {
 public:
  struct MysqlHandlerConf {
    std::string host;
    uint32_t port;
    std::string user;
    std::string pass;
    std::string database;
    std::string character_set = "utf8mb4";
  };
  using Conf = MysqlHandlerConf;

  class ResultHelp {
   public:
    explicit ResultHelp(MYSQL_RES *);
    ~ResultHelp();
    MYSQL_RES *Reply() const;
    bool Ok() const;
   private:
    MYSQL_RES *reply_;
  };

  MysqlHandler(const MysqlHandlerConf &conf);
  ~MysqlHandler();

  int32_t ExecuteQuery(const std::string &query) const;
  std::shared_ptr<ResultHelp> SelectData(const std::string &query) const;
  int64_t GetLastInsertId() const;
  std::string EscapeString(const std::string &raw) const;
  std::string EscapeStringQuote(const std::string &raw, char q = '\'') const;
  int32_t Transaction(const std::vector<std::string> &sqls) const;
  int32_t LastErrno() const;
  const std::string &LastErrMsg() const;

  template <typename ... Args>
  int32_t TransactionProc(Args && ... args) {
    if (connection_ == nullptr) {
      err_no_ = -1;
      return err_no_;
    }

    if (mysql_query(connection_, "begin") != 0) {
      err_no_ = mysql_errno(connection_);
      err_msg_ = mysql_error(connection_);
      LogWarn("sql 启动事务失败: " << err_no_ << " " << err_msg_);
      if (is_mysql_retry_errno(err_no_)) {
        ReConnect();
        if (connection_ == nullptr) {
          err_no_ = -1;
          return err_no_;
        }
        if (mysql_query(connection_, "begin") != 0) {
          err_no_ = mysql_errno(connection_);
          err_msg_ = mysql_error(connection_);
          LogWarn("sql 启动事务重试失败: " << err_no_ << " " << err_msg_);
          ReConnect();
          return err_no_;
        }
      } else {
        return err_no_;
      }
    }

    auto proc = [&](auto && arg) -> int32_t {
      using T = std::decay_t<decltype(arg)>;
      if constexpr (std::is_same_v<T, std::string> ||
                    std::is_same_v<T, const char *> ||
                    std::is_same_v<T, char *> ||
                    std::is_same_v<T, char []>) {
        const char *sql = nullptr;
        if constexpr (std::is_same_v<T, std::string>) {
          sql = arg.c_str();
        } else {
          sql = arg;
        }

        if (sql[0] == '\0') {  // 空串直接成功
          return 0;
        }

        if (mysql_query(connection_, sql) != 0) {
          err_no_ = mysql_errno(connection_);
          err_msg_ = mysql_error(connection_);
          LogWarn("sql 执行事务步骤失败: sql = " << sql
                  << " " << err_no_ << " " << err_msg_);
          ReConnect();
          return err_no_;
        }

        MYSQL_RES *result = mysql_store_result(connection_);
        if (result != nullptr) {
          mysql_free_result(result);
        }

        return 0;
      } else if constexpr (std::is_invocable_r_v<int32_t, T, MysqlHandler *>) {
        return arg(this);
      } else {
        static_assert(std::false_type::value, "unknow type.");
        return -1;  // 视为出错
      }
    };

    err_no_ = 0;
    ( ... && ((err_no_ = proc(std::forward<Args>(args))) == 0));
    if (err_no_ != 0) {
      if (mysql_query(connection_, "rollback") != 0) {
        err_no_ = mysql_errno(connection_);
        err_msg_ = mysql_error(connection_);
        LogWarn("sql 执行事务回滚失败: " << err_no_ << " " << err_msg_);
        ReConnect();
      }
      return err_no_;
    } else {
      if (mysql_query(connection_, "commit") != 0) {
        err_no_ = mysql_errno(connection_);
        err_msg_ = mysql_error(connection_);
        LogWarn("sql 执行事务提交失败: " << err_no_ << " " << err_msg_);
        ReConnect();
      }
    }

    return err_no_;
  }

  static MysqlHandler *Create(const Conf &);
  bool Alive() const;
 private:
  mutable MYSQL *connection_;
  const MysqlHandlerConf &conf_;

  bool DoConnect() const;
  bool ReConnect() const;
  mutable int32_t err_no_;
  mutable std::string err_msg_;
};

class MysqlProxy {
 public:
  MysqlProxy(const MysqlHandler::MysqlHandlerConf &conf);
  ~MysqlProxy() = default;

  int32_t ExecuteQuery(const std::string &query);
  std::shared_ptr<MysqlHandler::ResultHelp> SelectData(const std::string &query);
  MysqlProxy *operator->();

  template <typename ... Args>
  auto EscapeString(Args && ... args) {
    auto h = pool_.Get();

    auto r = std::make_tuple([](std::shared_ptr<MysqlHandler> &h,
                                auto &&arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::string>) {
          return h->EscapeString(arg);
        } else if constexpr (std::is_same_v<T, const char *> ||
                             std::is_same_v<T, char *> ||
                             std::is_same_v<T, char[]>) {
          return h->EscapeString(std::string(arg));
        } else {
          std::ostringstream oss;
          oss << arg;
          return h->EscapeString(oss.str());
        }
    }(h, std::forward<Args>(args))...);
    pool_.Put(h);
    return std::move(r);
  }

  template <typename ... Args>
  auto EscapeStringQuote(char q, Args && ... args) {
    auto h = pool_.Get();

    auto r = std::make_tuple([](std::shared_ptr<MysqlHandler> &h,
                                char q,
                                auto &&arg) -> std::string {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, std::string>) {
          return h->EscapeStringQuote(arg, q);
        } else if constexpr (std::is_same_v<T, const char *> ||
                             std::is_same_v<T, char *> ||
                             std::is_same_v<T, char[]>) {
          return h->EscapeStringQuote(std::string(arg), q);
        } else {
          std::ostringstream oss;
          oss << arg;
          return h->EscapeStringQuote(oss.str(), q);
        }
    }(h, q, std::forward<Args>(args))...);
    pool_.Put(h);
    return std::move(r);
  }

  int32_t Transaction(const std::vector<std::string> &sqls);
  template <typename ... Args>
  int32_t TransactionProc(Args && ... args) {
    auto h = pool_.Get();
    int32_t ret = h->TransactionProc(std::forward<Args>(args) ...);
    pool_.Put(h);

    return ret;
  }

  std::shared_ptr<MysqlHandler> GetHandler();
  void PutHandler(std::shared_ptr<MysqlHandler> h);

 private:
  miku::Pool<MysqlHandler> pool_;
};


template <uint32_t SC, uint32_t TC>
class MysqlRouter {
 public:
  MysqlRouter() = default;
  ~MysqlRouter() = default;
  bool Initailize(const std::vector<MysqlHandler::MysqlHandlerConf> &conf) {
    if (conf.size() != SC) {
      return false;
    }

    proxys_.resize(SC);
    for (uint32_t i = 0; i < SC; i++) {
      proxys_[i] = std::make_shared<MysqlProxy>(conf[i]);
    }

    return true;
  }

  template<typename T>
  std::tuple<std::shared_ptr<MysqlProxy>, uint32_t, uint32_t>
  GetProxy(const T &t) const {
    auto [ci, ti] = get_dbroute<SC, TC>(t);
    return {proxys_[ci], ci, ti};
  }

 private:
  std::vector<std::shared_ptr<MysqlProxy>> proxys_;
};


std::string mysql_help_escape_string(const std::string &raw);
std::string mysql_help_quote_string(const std::string &raw);
}  // namespace miku
