#include "result_buffer.h"

#include <stdio.h>
#include <stdlib.h>

__attribute__((visibility("default")))
ResultBuffer *encrypt_help_result_create() {
  ResultBuffer *r = (ResultBuffer *)malloc(sizeof(ResultBuffer));
  if (r != NULL) {
    encrypt_help_result_init(r);
  }

  return r;
}

__attribute__((visibility("default")))
void encrypt_help_result_destroy(ResultBuffer *r) {
  if (r != NULL) {
    if (r->d != NULL) {
      free(r->d);
    }

    free(r);
  }
}

__attribute__((visibility("default")))
void encrypt_help_result_init(ResultBuffer *r) {
  if (r != NULL) {
    r->d = NULL;
    r->n = 0;
  }
}

__attribute__((visibility("default")))
void encrypt_help_result_clear(ResultBuffer *r) {
  if (r != NULL) {
    if (r->d != NULL) {
      free(r->d);
      r->d = NULL;
    }

    r->n = 0;
  }
}
