#include "mysql_help.h"

#include <iostream>
#include "mysql/mysqld_error.h"

namespace miku {

bool
is_mysql_retry_errno(int32_t e) {
  return e == ER_CLIENT_INTERACTION_TIMEOUT || e == CR_SERVER_LOST;
}

MysqlHandler::ResultHelp::ResultHelp(MYSQL_RES *reply)
    : reply_(reply) {
  // nothing
}

MysqlHandler::ResultHelp::~ResultHelp() {
  if (reply_ != nullptr) {
    mysql_free_result(reply_);
  }
}

MYSQL_RES *
MysqlHandler::ResultHelp::Reply() const {
  return reply_;
}

bool
MysqlHandler::ResultHelp::Ok() const {
  return reply_ != nullptr;
}


int32_t
MysqlHandler::LastErrno() const {
  return err_no_;
}

const std::string &
MysqlHandler::LastErrMsg() const {
  return err_msg_;
}

MysqlHandler::MysqlHandler(const MysqlHandlerConf &conf)
    : connection_(nullptr)
    , conf_(conf) {
  ReConnect();
}

MysqlHandler::~MysqlHandler() {
  if (connection_ != nullptr) {
    mysql_close(connection_);
    connection_ = nullptr;
  }
}

bool
MysqlHandler::DoConnect() const {
  if (mysql_real_connect(connection_, conf_.host.c_str(), conf_.user.c_str(),
        conf_.pass.c_str(), conf_.database.c_str(), conf_.port, nullptr, 0)) {
    if (mysql_set_character_set(connection_,
                                conf_.character_set.c_str()) != 0) {
      LogWarn("设置字符集失败 : " << conf_.character_set);
      return false;
    }
    return true;
  } else {
    LogWarn("连接失败: " << mysql_errno(connection_)
             << " " << mysql_error(connection_));
    return false;
  }
}

bool MysqlHandler::ReConnect() const {
  if (connection_ != nullptr) {
    mysql_close(connection_);
    connection_ = nullptr;
  }

  connection_ = mysql_init(connection_);
  if (connection_ == nullptr || !DoConnect()) {
    mysql_close(connection_);
    connection_ = nullptr;
    return false;
  }

  return true;
}

int64_t
MysqlHandler::GetLastInsertId() const {
  if (connection_ == nullptr) {
    return -1;
  }
  return mysql_insert_id(connection_);
}

int32_t
MysqlHandler::ExecuteQuery(const std::string &query) const {
  if (connection_ == nullptr) {
    err_no_ = -1;
    return err_no_;
  }

  if (mysql_query(connection_, query.c_str()) != 0) {
    if (!is_mysql_retry_errno(mysql_errno(connection_)) ||
        !ReConnect() ||
        mysql_query(connection_, query.c_str()) != 0) {
      err_no_ = mysql_errno(connection_);
      err_msg_ = mysql_error(connection_);
      LogWarn("sql语句执行失败: " << err_no_ << " " << err_msg_);
      return err_no_;
    }
  }

  MYSQL_RES *result = mysql_store_result(connection_);
  if (result != nullptr) {
    mysql_free_result(result);
  }

  err_no_ = 0;
  err_msg_ = "";
  return err_no_;
}

std::shared_ptr<MysqlHandler::ResultHelp>
MysqlHandler::SelectData(const std::string &query) const {
  if (mysql_query(connection_, query.c_str()) != 0) {
    if (!is_mysql_retry_errno(mysql_errno(connection_)) ||
        !ReConnect() ||
        mysql_query(connection_, query.c_str()) != 0) {
      err_no_ = mysql_errno(connection_);
      err_msg_ = mysql_error(connection_);
      LogWarn("查询失败: " << err_no_ << " " << err_msg_);
      ReConnect();
      return std::make_shared<MysqlHandler::ResultHelp>(nullptr);
    }
  }

  MYSQL_RES *result = mysql_store_result(connection_);
  if (result == nullptr) {
    err_no_ = mysql_errno(connection_);
    err_msg_ = mysql_error(connection_);
    LogWarn("获取结果集失败: " << err_no_ << " " << err_msg_);
    ReConnect();
    return std::make_shared<MysqlHandler::ResultHelp>(nullptr);
  }

  err_no_ = 0;
  err_msg_ = "";
  return std::make_shared<MysqlHandler::ResultHelp>(result);
}

MysqlHandler *MysqlHandler::Create(const Conf &conf) {
  return new MysqlHandler(conf);
}

bool MysqlHandler::Alive() const {
  return connection_ != nullptr;
}

std::string
MysqlHandler::EscapeString(const std::string &raw) const {
  if (connection_ == nullptr) {
    return std::string("");
  }
  std::shared_ptr <char []> pbuf(new char[raw.length() * 2 + 1]);

  // 返回写入的字符数，会自动写'\0'
  mysql_real_escape_string(connection_, pbuf.get(), raw.c_str(), raw.length());
  return std::string(pbuf.get());
}

std::string
MysqlHandler::EscapeStringQuote(const std::string &raw, char q) const {
  if (connection_ == nullptr) {
    return std::string("");
  }
  std::shared_ptr <char []> pbuf(new char[raw.length() * 2 + 1]);

  // 返回写入的字符数，会自动写'\0'
  //auto r = mysql_real_escape_string_quote(
  //    connection_, pbuf.get(), raw.c_str(), raw.length(), q);
  //pbuf.get[r] = '\0';
  mysql_real_escape_string_quote(
      connection_, pbuf.get(), raw.c_str(), raw.length(), q);
  return std::string(pbuf.get());
}

int32_t
MysqlHandler::Transaction(const std::vector<std::string> &sqls) const {
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

  for (const auto &sql : sqls) {
    if (mysql_query(connection_, sql.c_str()) != 0) {
      err_no_ = mysql_errno(connection_);
      err_msg_ = mysql_error(connection_);
      LogWarn("sql 执行事务步骤失败: sql = " << sql
              << " "<< err_no_ << " " << err_msg_);
      if (mysql_query(connection_, "rollback") != 0) {
        err_no_ = mysql_errno(connection_);
        err_msg_ = mysql_error(connection_);
        LogWarn("sql 执行事务回滚失败: " << err_no_ << " " << err_msg_);
        ReConnect();
      }
      return err_no_;
    }

    MYSQL_RES *result = mysql_store_result(connection_);
    if (result != nullptr) {
      mysql_free_result(result);
    }
  }

  if (mysql_query(connection_, "commit") != 0) {
    err_no_ = mysql_errno(connection_);
    err_msg_ = mysql_error(connection_);
    LogWarn("sql 执行事务提交失败: " << err_no_ << " " << err_msg_);
    ReConnect();
    return err_no_;
  }

  err_no_ = 0;
  err_msg_ = "";
  return err_no_;



#if 0
  if (mysql_query(connection_, query.c_str()) != 0) {
    if (!is_mysql_retry_errno(mysql_errno(connection_)) ||
        !ReConnect() ||
        mysql_query(connection_, query.c_str()) != 0) {
      err_no_ = mysql_errno(connection_);
      err_msg_ = mysql_error(connection_);
      LogWarn("sql语句执行失败: " << err_no_ << " " << err_msg_);
      return err_no_;
    }
  }

  MYSQL_RES *result = mysql_store_result(connection_);
  if (result != nullptr) {
    mysql_free_result(result);
  }
#endif

  err_no_ = 0;
  err_msg_ = "";
  return err_no_;
}


MysqlProxy::MysqlProxy(const MysqlHandler::MysqlHandlerConf &conf)
    : pool_(conf) {
}

int32_t
MysqlProxy::ExecuteQuery(const std::string &query) {
  auto mysql = pool_.Get();
  if (mysql == nullptr) {
    return -1;
  }

  int32_t ret = mysql->ExecuteQuery(query);
  pool_.Put(mysql);

  return ret;
}

std::shared_ptr<MysqlHandler::ResultHelp>
MysqlProxy::SelectData(const std::string &query) {
  auto mysql = pool_.Get();
  if (mysql == nullptr) {
    return std::make_shared<MysqlHandler::ResultHelp>(nullptr);
  }

  auto ret = mysql->SelectData(query);
  pool_.Put(mysql);

  return ret;
}

MysqlProxy *
MysqlProxy::operator->() {
  return this;
}

int32_t
MysqlProxy::Transaction(const std::vector<std::string> &sqls) {
  auto mysql = pool_.Get();
  if (mysql == nullptr) {
    return -1;
  }

  auto ret = mysql->Transaction(sqls);
  pool_.Put(mysql);

  return ret;
}

std::shared_ptr<MysqlHandler>
MysqlProxy::GetHandler() {
  return pool_.Get();
}

void
MysqlProxy::PutHandler(std::shared_ptr<MysqlHandler> h) {
  pool_.Put(h);
}

std::string
mysql_help_escape_string(const std::string &raw) {
  std::shared_ptr <char []> pbuf(new char[raw.length() * 2 + 1]);

  // 返回写入的字符数，会自动写'\0'
  mysql_escape_string(pbuf.get(), raw.c_str(), raw.length());
  return std::string(pbuf.get());
}

std::string
mysql_help_quote_string(const std::string &raw) {
  std::shared_ptr <char []> pbuf(new char[raw.length() * 2 + 3]);
  pbuf.get()[0] = '\'';

  // 返回写入的字符数，会自动写'\0'
  auto ret = mysql_escape_string(pbuf.get() + 1, raw.c_str(), raw.length());
  pbuf.get()[ret + 1] = '\'';
  pbuf.get()[ret + 2] = '\0';
  return std::string(pbuf.get());
}

}  // namespace miku
