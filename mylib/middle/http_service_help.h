#pragma once

#include "event.h"
#include "evhttp.h"
#include "util/util.h"
#include "util/log.h"
#include "util/protobuf_convert.h"
#include "encrypt_help/hash.h"
#include "middle/client_help.h"
#include "middle/auto_rpc_log.h"

namespace miku::http_service {
DECLARE_MEMBER_CHECK(ret)
DECLARE_MEMBER_CHECK(status)
DECLARE_MEMBER_CHECK(code)

template <typename T>
void
http_call_failed_reply(struct evhttp_request *req,
                       const std::string &e_msg,
                       T *rsp) {
  struct evbuffer *response_buffer = evbuffer_new();
  if constexpr (CheckHas_ret<T>::value) {
    rsp->set_ret(static_cast<decltype(rsp->ret())>(-1));
  } else if constexpr (CheckHas_status<T>::value) {
    rsp->set_status(static_cast<decltype(rsp->status())>(501));
  } else if constexpr (CheckHas_code<T>::value) {
    rsp->set_code(static_cast<decltype(rsp->code())>(501));
  }

  rsp->set_msg(e_msg);
  std::string str_rsp;
  miku::protobuf_to_json(*rsp, &str_rsp, true);

  evhttp_add_header(req->output_headers, "Content-Type", "application/json; charset=utf-8");

  evbuffer_add(response_buffer, str_rsp.c_str(), str_rsp.length());
  evhttp_send_reply(req, HTTP_OK, "OK", response_buffer);
  evbuffer_free(response_buffer);
  return;
}

template <typename T>
void
http_call_success_reply(struct evhttp_request *req,
                        const T &rsp) {
  struct evbuffer *response_buffer = evbuffer_new();
  std::string str_rsp;
  miku::protobuf_to_json(rsp, &str_rsp, true);

  evhttp_add_header(req->output_headers, "Content-Type", "application/json; charset=utf-8");

  evbuffer_add(response_buffer, str_rsp.c_str(), str_rsp.length());
  evhttp_send_reply(req, HTTP_OK, "OK", response_buffer);
  evbuffer_free(response_buffer);
  return;
}

template <typename HDR>
int32_t
auth_http_hdr(
    const HDR &h,
    std::function<std::optional<std::string> (const std::string &)> get_key,
    std::string *emsg = nullptr) {
  const auto &appid = h.appid();
  const auto &timestamp = h.timestamp();
  const auto &v = h.v();
  const auto &nonce = h.nonce();
  const auto &echostr = h.echostr();
  const auto &sign = h.sign();

  if (appid.empty()) {
    if (emsg != nullptr) *emsg = "appid is empty.";
    return 102;
  }

  auto key = get_key(appid);
  //const auto *pkey = auth_keys_->GetValue({appid});
  if (!key) {
    if (emsg != nullptr) *emsg = "appid not found";
    return 102;
  }

  time_t tnow = time(nullptr);
  int64_t offset = timestamp > tnow ? timestamp - tnow : tnow - timestamp;
  if (offset > 300) {
    if (emsg != nullptr) *emsg = "erro timestamp";
    return 103;
  }

  if (v != std::string("1.0")) {
    if (emsg != nullptr) *emsg = "v must be 1.0";
    return 104;
  }

  if (nonce.empty()) {
    if (emsg != nullptr) *emsg = "nonce is empty";
    return 105;
  }

  std::stringstream ss_to_sign;
  ss_to_sign << appid << echostr << nonce << timestamp << v << *key;
  std::string s_to_sign = ss_to_sign.str();
  char md5buf[33] = "";

  miku_hex_md5(reinterpret_cast<const uint8_t *>(s_to_sign.c_str()),
      s_to_sign.length(),
      nullptr,
      0,
      md5buf,
      sizeof(md5buf));
  std::string lsign = sign;
  std::transform(lsign.begin(), lsign.end(), lsign.begin(), ::tolower);
  if (strcmp(lsign.c_str(), md5buf + 16) != 0) {
    if (emsg != nullptr) *emsg = "sign check failed.";
    return 106;
  }

  return 0;
}

void http_request_handler_default(struct evhttp_request *req, void *arg);

}



#ifndef HTTP_HELP_FUNCATION_DECLARE
# define HTTP_HELP_FUNCATION_DECLARE(CN, PN, SV, N, n)                      \
namespace PN {                                                              \
void httpd_handler_##n(struct evhttp_request *req, void *arg);              \
}
#endif

#ifndef HTTP_HELP_FUNCATION_IMPL
# define HTTP_HELP_FUNCATION_IMPL(CN, PN, SV, N, n)                         \
namespace PN {                                                              \
void                                                                        \
httpd_handler_##n(struct evhttp_request *req, void *arg) {                  \
  const auto &client_proxy = CLIENT_HELP_PROXY(CN);                         \
  PN::N##Req r;                                                             \
  PN::N##Resp rsp;                                                          \
  std::string d = std::string(                                              \
        reinterpret_cast<const char *>(EVBUFFER_DATA(req->input_buffer)),   \
        req->body_size);                                                    \
  bool ret = miku::json_to_protobuf(d, &r);                                 \
  if (!ret) {                                                               \
    LogInfo("parse msg failed. " << d);                                     \
    miku::http_service::http_call_failed_reply(req, "unknow msg.", &rsp);   \
    return;                                                                 \
  }                                                                         \
                                                                            \
  auto auto_print = AUTO_LOG_HTTP(r, rsp);                                  \
  ret = client_proxy->N(r, &rsp);                                           \
  if (!ret) {                                                               \
    miku::http_service::http_call_failed_reply(                             \
        req, "server is busy.", &rsp);                                      \
    return;                                                                 \
  }                                                                         \
                                                                            \
  miku::http_service::http_call_success_reply(req, rsp);                    \
  return;                                                                   \
}                                                                           \
}
#endif

#ifndef HTTP_HELP_GRPC_REGISTER_CB
# define HTTP_HELP_GRPC_REGISTER_CB(CN, PN, SV, N, n)                       \
  RegisterHttpCb(miku::str_replace(#PN "::" #SV, "::", "."),                \
                 #n,                                                        \
                 PN::httpd_handler_##n,                                     \
                 nullptr);

#endif

#ifndef HTTP_HELP_DEFAULT_REGISTER_CB
# define HTTP_HELP_DEFAULT_REGISTER_CB(CN, PN, SV, N, n)                    \
  RegisterHttpCb(#n,                                                        \
                 PN::httpd_handler_##n,                                     \
                 nullptr);

#endif

#ifndef HTTP_HELP_GRPC_SERVICE_SV
# define HTTP_HELP_GRPC_SERVICE_SV(PN, SV)                                  \
  miku::str_replace(#PN "::" #SV, "::", ".")

#endif
