#ifndef ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_RESULT_BUFFER_H_
#define ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_RESULT_BUFFER_H_

#ifdef __cplusplus
extern "C" {
#endif  //  __cplusplus

#include <stddef.h>

// 保存结果数据的buffer结构
typedef struct ResultBuffer {
  void *d;  // 数据所在地址
  size_t n;  // 数据的长度
} ResultBuffer;

// 创建结果的结构体
ResultBuffer *encrypt_help_result_create();
// 删除结果结构体，调用此接口不需要单独做clear
void encrypt_help_result_destroy(ResultBuffer *r);

// 初始化结果结构体，结构体本身的内存由调用者维护
void encrypt_help_result_init(ResultBuffer *r);
// 清除结果数据
void encrypt_help_result_clear(ResultBuffer *r);

#ifdef __cplusplus
}
#endif  //  __cplusplus

#endif  //  ENCRYPT_HELP_INCLUDE_ENCRYPT_HELP_RESULT_BUFFER_H_
