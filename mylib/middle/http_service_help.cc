#include "http_service_help.h"

namespace miku::http_service {
void
http_request_handler_default(
    struct evhttp_request *req, void *arg) {
  struct evbuffer *response_buffer = evbuffer_new();
  if (!response_buffer) {
    LogWarn("Failed to create response buffer");
    return;
  }

  LogDebug("unknow msg");
  const char *uri = evhttp_request_get_uri(req);  //http的get和delete请求不能带body，只能通过uri带参
  int method = evhttp_request_get_command(req);
  const char *content_type = evhttp_find_header(req->input_headers, (const char*)"Content-Type");
  LogDebug("content_type = " << content_type);

  int length = req->body_size;
  char *body = (char*)EVBUFFER_DATA(req->input_buffer);

  LogDebug("uri = " << uri);
  if (EVHTTP_REQ_GET == method) {
    LogDebug("method = GET");
  } else if (EVHTTP_REQ_POST == method) {
    LogDebug("method = POST");
  } else if (EVHTTP_REQ_PUT == method) {
    LogDebug("method = PUT");
  } else if (EVHTTP_REQ_DELETE == method) {
    LogDebug("method = DELETE");
  }

  if (length > 0) {
    LogDebug("body = " << std::string(body, length));
  }



  // std::cout << std::this_thread::get_id() << std::endl;

  // 设置响应内容
  //evbuffer_add_printf(response_buffer, "Hello, HTTPS World!\n");

  // 设置 HTTP 响应头和返回内容
  evhttp_send_reply(req, HTTP_NOTFOUND, "", response_buffer);

  // 释放响应缓冲区
  evbuffer_free(response_buffer);
}
}
