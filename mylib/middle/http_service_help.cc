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
  // std::cout << std::this_thread::get_id() << std::endl;

  // 设置响应内容
  //evbuffer_add_printf(response_buffer, "Hello, HTTPS World!\n");

  // 设置 HTTP 响应头和返回内容
  evhttp_send_reply(req, HTTP_NOTFOUND, "", response_buffer);

  // 释放响应缓冲区
  evbuffer_free(response_buffer);
}
}
