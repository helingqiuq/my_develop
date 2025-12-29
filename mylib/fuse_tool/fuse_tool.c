#define FUSE_USE_VERSION 30

#include <fuse.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <dlfcn.h>
#include "encrypt_help/encrypt.h"

// '#',':','\','?'需要转义; \# -> #; \: -> : \\ -> \ \? -> ?
// ':'用于字段分割
// '#','?'用于校验标识，如/tmp/123#md512345678901234567890123456789012
//  表示对/tmp/123文件进行md5值的校验，后续可增加校验方式
//  '?'是对'#'标识字段的标识，对#后的内容生效，如/bin/python#script/root/x.py?md512345678901234567890123456789012
//  以/bin/python启动/root/x.py的python脚本，该脚本的md5值进行校验
//
//  #md5 校验md5值
//  #pid 校验pid
//  #script 检验可执行程序的第一个非'-'开头的参数

#define MAX_PATH_LEN 1024

#define TRY_FREE_PROC(x) do { \
    if (x != NULL) {          \
      free(x);                \
      x = NULL;               \
    }                         \
  } while (0)

static char s_cur_module_path[MAX_PATH_LEN];
static char s_cur_work_path[MAX_PATH_LEN];
// {{{ logger
FILE *log_fp = NULL;
int log_output = 0;
__attribute__((format(printf, 4, 5))) static void
logger(const char *file, unsigned int l, const char *fun, const char *fmt, ...);
#define LOGGER(fmt...) logger(__FILE__, __LINE__, __FUNCTION__, fmt)
// }}}

// {{{ commom funcation
typedef unsigned long (*get_buffer_size_t)(
    void *inbuf, unsigned long inbuf_len, int argc, char *argv[]);
typedef int (*transform_t)(void *inbuf, unsigned long inbuf_len,
                           void *outbuf, unsigned long outbuf_len,
                           int argc, char *argv[]);

static unsigned long default_get_buffer_size(
    void *inbuf, unsigned long inbuf_len, int argc, char *argv[]) {
  return inbuf_len;
}

static int
default_transfer_proc(
    void *inbuf, unsigned long inbuf_len,
    void *outbuf, unsigned long outbuf_len,
    int unuse__, char *unuse2__[]) {
  if (inbuf_len == 0) {
    return 1;
  }

  memcpy(outbuf, inbuf, inbuf_len);
  return 0;
}

static int
is_escape(const char *beg, const char *cur, const char escape) {
  int i = 0;
  cur--;
  while (cur >= beg && *cur-- == escape) {
    i++;
  }

  return i % 2 == 1;
}

static char *
split_string_dup(const char *beg, const char escape, const char **cur) {
  if (beg == NULL) {
    return NULL;
  }

  const char *p = beg;
  while (*p != '\0') {
    if (*p == escape && !is_escape(beg, p, '\\')) {
      break;
    }
    p++;
  }

  unsigned len = p - beg;
  if (cur != NULL) {
    *cur = (*p == escape) ? (p + 1) : NULL;
  }

  char *d = (char *)malloc(len + 1);
  char *pbuf = d;

  memset(d, 0, len + 1);

  for (;beg < p; beg++, pbuf++) {
    if (*beg == '\\' && beg + 1 < p && *(beg + 1) == escape) {  // 一定是转义的
      *pbuf = escape;
      beg++;
    }
    *pbuf = *beg;
  }

  return d;
}

static int
str_escape(const char *path, int index) {
  const char *p;
  int n = 0;
  if (index < 0) {
    return 0;
  }

  p = path + index;

  while (p >= path && *p == '\\') {
    n++;
    p--;
  }

  return n % 2;
}

static int
clean_full_path(char *path) {
  int len = strlen(path);
  int i;
  int j;

  if (len == 0) {
    return -1;
  }

  if (path[0] != '/') {
    /* 这里只支持绝对路径 */
    return -1;
  }

  /* 去掉 "//" */
  for (i = len - 1; i >= 0; i--) {
    if (path[i] == '/' && path[i + 1] == '/'
        && !str_escape(path, i - 1)) {
      len -= 1;
      for (j = i; j < len; j++) {
        path[j] = path[j + 1];
      }
      path[len] = '\0';
    }
  }

  /* 去掉 "/." */
  for (i = len - 1; i >= 0; i--) {
    if (i >= 1
        && path[i] == '.'
        && path[i - 1] == '/'
        && (path[i + 1] == '/' || path[i + 1] == '\0')
        && !str_escape(path, i - 2)) {
      /* 找到 "./" */
      i--;
      len -= 2;
      for (j = i; j < len; j++) {
        path[j] = path[j + 2];
      }
      path[len] = '\0';
    }
  }

  /* 去掉 "/.." */
  int n = 0;
  int offset = 0;
  for (i = len - 1; i >= 0; i--) {
    if (i >= 2
        && path[i] == '.'
        && path[i - 1] == '.'
        && path[i - 2] == '/'
        && (path[i + 1] == '\0' || path[i + 1] == '/')
        && !str_escape(path, i - 3)) {
      n++;
      len -= 3;
      i -= 2; /* continue 后i会再自减1 */
      offset += 3;
    } else if (path[i] == '/'
        && !str_escape(path, i - 1)) {
      /* 如果没有处于 "/.."状态，则直接继续即可 */
      if (n == 0) {
        continue;
      }

      /* 如果处于"/.."状态，向前找到 '/', 并计算offset */
      n--;
      offset++;
      len--;
      if (n == 0) {
        for (j = i; j < len; ++j) {
          path[j] = path[j + offset];
        }

        path[len] = '\0';
        offset = 0;
      }
    } else {
      if (n > 0) {
        offset++;
        len--;
      }
    }
  }

  if (n > 0) {
    /* 保留根目录 */
    for (j = 1; j < len; ++j) {
      path[j] = path[j + offset];
    }

    path[len] = '\0';
  }

  if (len == 0) {
    path[0] = '/';
    path[1] = '\0';
  }

  return 0;
}

static void format_pid_info_cmd(char *cmd, unsigned int cmd_l,
                                pid_t pid, const char *sub_path) {
  if (pid == 0) {
    snprintf(cmd, cmd_l, "/proc/self/%s", sub_path);
  } else {
    snprintf(cmd, cmd_l, "/proc/%d/%s", pid, sub_path);
  }
}

static char *
get_module_path(char *buffer, int l, pid_t pid) {
  char cmd[64] = {0};
  format_pid_info_cmd(cmd, sizeof(cmd), pid, "exe");

  char buf[MAX_PATH_LEN] = {0};
  if (buffer == NULL) {
    LOGGER("path is null.");
    return NULL;
  }

  ssize_t n = readlink(cmd, buf, sizeof(buf));
  if (n == -1) {
    LOGGER("readlink failed. cmd : [%s], errno : [%d]\n", cmd, errno);
    return NULL;
  }

  if (n >= sizeof(buf)) {
    LOGGER("read_path is too long. size : [%lu]\n", n);
    return NULL;
  }

  snprintf(buffer, l, "%s", buf);
  return buffer;
}

static char *
get_file_md5(const char *file, char md5buffer[33]) {
  FILE *fp = fopen(file, "rb");
  if (fp == NULL) {
    LOGGER("fopen file failed. file : [%s]", file);
    return NULL;
  }

  fseek(fp, 0, SEEK_END);
  unsigned long l = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  char *buf = (char *)malloc(l);
  if (buf == NULL) {
    LOGGER("malloc failed.");
    fclose(fp);
    return NULL;
  }

  long ret = fread(buf, 1, l, fp);
  if (ret != l) {
    LOGGER("failed failed. ret : [%ld], l : [%lu]", ret, l);
    free(buf);
    fclose(fp);
    return NULL;
  }
  fclose(fp);

  miku_hex_md5((const unsigned char *)buf, l, NULL, 0, md5buffer, 33);
  free(buf);

  return md5buffer;
}

// default_type，当路径为相对路径时的路径选取。
// 0，从pwd进行相对路径补充
// 1，从module_path进行相对路径补充
// 其它，从pwd进行相对路径补充
static char *
get_absolute_path(const char *path_src,
                  char *path_des,
                  int l,
                  int default_type) {
  if (path_src == NULL || path_des == NULL) {
    return NULL;
  }

  int len = strlen(path_src);
  if (len >= MAX_PATH_LEN) {
    return NULL;
  }

  char buf[MAX_PATH_LEN * 2] = {0};

  /* 如果第一位是'/'，则已经是绝对路径 */
  if (path_src[0] == '/') {
    strncpy(buf, path_src, sizeof(buf) - 1);
  } else {
    switch (default_type) {
     case 1:
      snprintf(buf, sizeof(buf), "%s/%s", s_cur_module_path, path_src);
      break;
     case 0:
     default:
      snprintf(buf, sizeof(buf), "%s/%s", s_cur_work_path, path_src);
      break;
    }
  }

  if (clean_full_path(buf) != 0) {
    return NULL;
  }

  if (strlen(buf) >= l) {
    return NULL;
  }

  strcpy(path_des, buf);

  return path_des;
}

static char *
get_module_script(char *buffer, int l, pid_t pid) {
  char cmd[64] = {0};
  format_pid_info_cmd(cmd, sizeof(cmd), pid, "cmdline");

  if (buffer == NULL) {
    return NULL;
  }

  FILE *fp = fopen(cmd, "r");
  if (fp == NULL) {
    return NULL;
  }

  char buf[4096];
  fseek(fp, 0, SEEK_SET);
  long total = fread(buf, 1, sizeof(buf), fp);  // 最好不要超过4096，是可能失败的
  fclose(fp);
  if (total <= 0) {
    return NULL;
  }

  char *p = buf;
  // 略过第一个
  p += strlen(p) + 1;
  while (p - buf < total) {
    if (*p == '-') {
      p += strlen(p) + 1;
      continue;
    }

    if (p[0] == '/') {  // 完整路径
      strcpy(buffer, p);
      return buffer;
    }

    format_pid_info_cmd(cmd, sizeof(cmd), pid, "cwd");
    char buf_cwd[4096] = {0};  // 超过4096，是可能失败的
    ssize_t n = readlink(cmd, buf_cwd, sizeof(buf_cwd));
    if (n < 0) {
      return NULL;
    }
    strcat(buf_cwd, "/");
    strcat(buf_cwd, p);
    clean_full_path(buf_cwd);
    strcpy(buffer, buf_cwd);

    return buffer;
  }

  return NULL;
}
// }}}

// 转换函数
static transform_t s_default_transform_proc = default_transfer_proc;
// 计算需要buffer的函数
static get_buffer_size_t
s_default_get_buffer_size_proc = default_get_buffer_size;

// {{{ VectorStu
typedef struct VectorStu {
  int n;
  void *d[0];
} VectorStu;

// 返回0遍历继续，其它遍历中止
typedef int (*vector_do_proc)(void *d, void *arg);
typedef void *(*vector_do_create_proc)(const void *d,
                                       unsigned int l,
                                       void *arg);

// NULL遍历完所有结点，其它为proc函数返回停止时的结点
static void *
vector_for_each(const VectorStu *vdatas, vector_do_proc proc, void *arg) {
  if (vdatas == NULL) {
    return NULL;
  }

  for (int i = 0; i < vdatas->n; i++) {
    if (proc(vdatas->d[i], arg) != 0) {
      return vdatas->d[i];
    }
  }

  return NULL;
}

static void *
vector_push_back(VectorStu **vdatas,
                 const void *d,
                 unsigned int l,
                 vector_do_create_proc proc,
                 void *arg) {
  if (vdatas == NULL) {
    return NULL;
  }

  // 创建新的结点
  void *pnd = NULL;
  if (proc == NULL) {
    pnd = malloc(l);
    memcpy(pnd, d, l);
  } else {
    pnd = proc(d, l, arg);
    if (pnd == NULL) {  // 创建失败就会加入失败
      return NULL;
    }
  }

  VectorStu *pold = *vdatas;
  int ndatas = 0;
  if (pold == NULL) {
    ndatas = 0;
  } else {
    ndatas = pold->n;
  }

  VectorStu *pnew = (VectorStu *)malloc(
                    sizeof(VectorStu) + sizeof(char *) * (ndatas + 1));
  if (pnew == NULL) {
    LOGGER("malloc failed.");
    exit(0);
  }
  pnew->n = ndatas + 1;
  // 旧的复制过来
  for (int i = 0; i < ndatas; i++) {
    pnew->d[i] = pold->d[i];
  }

  pnew->d[ndatas] = pnd;

  *vdatas = pnew;
  free(pold);
  return pnd;
}

static void
vector_clear(VectorStu **args, vector_do_proc proc, void *arg) {
  if (args == NULL || *args == NULL) {
    return;
  }

  VectorStu *pargs = *args;
  if (proc == NULL) {
    for (int i = 0; i < pargs->n; i++) {
      free(pargs->d[i]);
    }
  } else {
    for (int i = 0; i < pargs->n; i++) {
      proc(pargs->d[i], arg);
      free(pargs->d[i]);
    }
  }

  free(pargs);
  *args = NULL;
  return;
}
// }}}

// {{{ MyfsBuffer
typedef struct MyfsBuffer {
  unsigned long n;      // d的长度
  unsigned char d[0];
} MyfsBuffer;
// }}}

//  {{{ transform_lib防重保存的结构
typedef struct TransformLibStu {
  char *path;
  void *h_lib;
  get_buffer_size_t get_size_proc;
  transform_t transform_proc;
} TransformLibStu;

static void
clear_transfor_lib_stu(TransformLibStu *pstu, void *arg) {
  if (pstu == NULL) {
    return;
  }
  TRY_FREE_PROC(pstu->path);
  dlclose(pstu->h_lib);
  pstu->h_lib = NULL;
  pstu->get_size_proc = NULL;
  pstu->transform_proc = NULL;
}

static VectorStu *s_transform_libs = NULL;
// 加入新的转码共享库，如果已存在则返回已有的结构体指针
static int
check_has_transform_lib_proc(TransformLibStu *d, char *lib_file) {
  if (strcmp(d->path, lib_file) == 0) {
    return 1;
  }

  return 0;
}

static TransformLibStu *
append_transform_lib(VectorStu **ptransform_libs, const char *lib_file) {
  if (ptransform_libs == NULL) {
    return NULL;
  }

  TransformLibStu *p = (TransformLibStu *)vector_for_each(
      *ptransform_libs,
      (vector_do_proc)check_has_transform_lib_proc,
      (void *)lib_file);
  if (p != NULL) {  // 已存在
    return p;
  }

  TransformLibStu stu = {0};
  if (lib_file != NULL) {
    stu.h_lib = dlopen(lib_file, RTLD_NOW | RTLD_LOCAL);
    if (stu.h_lib == NULL) {
      LOGGER("dlopen [%s] failed.", lib_file);
      return NULL;
    }
  }

  stu.get_size_proc = (get_buffer_size_t)dlsym(
      stu.h_lib, "get_need_buffer_size");
  if (stu.get_size_proc == NULL) {
    stu.get_size_proc = s_default_get_buffer_size_proc;
  }

  stu.transform_proc = (transform_t)dlsym(stu.h_lib, "transform");
  if (stu.transform_proc == NULL) {
    stu.transform_proc = s_default_transform_proc;
  }
  stu.path = strdup(lib_file);  // 删除时再清理这部分内存

  p = (TransformLibStu *)vector_push_back(
      ptransform_libs, (void *)&stu, sizeof(stu), NULL, NULL);
  return p;
}

static void
clear_all_transform_lib_stu(VectorStu **transform_libs) {
  vector_clear(transform_libs, (vector_do_proc)clear_transfor_lib_stu, NULL);
}
// }}}

// {{{ FileCheckStu
typedef struct FileCheckStu {
  char *file_path;  // 文件路径
  char *file_md5;  // 校验文件的md5
  char *sub_file;  // 执行脚本时指定脚本
  char *sub_file_md5;  // 脚本的md5校验
  char *pid;  //  file_path为该pid的执行文件
} FileCheckStu;

static void
file_check_stu_clear(FileCheckStu *pstu, void *arg) {
  TRY_FREE_PROC(pstu->file_path);
  TRY_FREE_PROC(pstu->file_md5);
  TRY_FREE_PROC(pstu->sub_file);
  TRY_FREE_PROC(pstu->sub_file_md5);
  TRY_FREE_PROC(pstu->pid);
}

// /tmp/my_exec#md512345678901234567890123456789012?md5666
static void
clear_escape(char *pstr) {
  if (pstr == NULL) {
    return;
  }

  char *p1 = pstr;
  char *p2 = pstr;

  while (*p2 != '\0') {
    if (*p2 == '\\') {
      p2++;
      if (*p2 == '\0') {
        break;
      }
    }
    *p1++ = *p2++;
  }
  *p1 = '\0';
}

static void
cmd_to_file_check_stu(const char *cmd, FileCheckStu *pstu) {
  const char *pstr = cmd;
  FileCheckStu stu;
  memset((void *)&stu, 0, sizeof(stu));
  while (pstr != NULL) {
    char *ptmp_str = split_string_dup(pstr, '#', &pstr);
    if (stu.file_path == NULL) {  // 第一个，一定是文件路径
      char buffer[MAX_PATH_LEN] = {0};
      char *file_path = split_string_dup(ptmp_str, '?', NULL);
      get_absolute_path(file_path, buffer, sizeof(buffer), 0);
      stu.file_path = strdup(buffer);
      free(file_path);
    } else if (strncmp(ptmp_str, "md5", 3) == 0) {
      stu.file_md5 = split_string_dup(ptmp_str + 3, '?', NULL);
    } else if (strncmp(ptmp_str, "pid", 3) == 0) {
      stu.pid = split_string_dup(ptmp_str + 3, '?', NULL);
    } else if (strncmp(ptmp_str, "script", 6) == 0) {
      const char *pstr_sub = ptmp_str + 6;
      while (pstr_sub != NULL) {
        char *ptmp_str_sub = split_string_dup(pstr_sub, '?', &pstr_sub);
        if (stu.sub_file == NULL) {
          char buffer[MAX_PATH_LEN] = {0};
          get_absolute_path(ptmp_str_sub, buffer, sizeof(buffer), 0);
          stu.sub_file = strdup(buffer);
        } else if (strncmp(ptmp_str_sub, "md5", 3) == 0) {
          stu.sub_file_md5 = strdup(ptmp_str_sub + 3);
        }  // 后面有再补充

        free(ptmp_str_sub);
      }
    }  // 后面有再补充

    free(ptmp_str);
  }

  if (pstu != NULL) {
    *pstu = stu;
    clear_escape(pstu->file_path);
    //clear_escape(pstu->file_md5);
    clear_escape(pstu->sub_file);
    //clear_escape(pstu->sub_file_md5);
  } else {
    file_check_stu_clear(&stu, NULL);
  }
}

// bool值，非0通过检查，0不通过
// 只做文件合法性检查，文件许可性检查在上级做
static int
do_file_check(const struct FileCheckStu *fc,
              int must_file_md5,
              int must_sub_file_md5) {
  char md5buffer[33] = {0};
  if (fc->file_path == NULL) {
    LOGGER("file_path is NULL.\n");
    return 0;
  }

  if (must_file_md5 && fc->file_md5 == NULL) {
    LOGGER("must check file md5, but not set.\n");
    return 0;
  }

  if (must_sub_file_md5 &&
      (fc->sub_file == NULL || fc->sub_file_md5 == NULL)) {
    LOGGER("must check sub_file md5, but not set.\n");
    return 0;
  }

  if (fc->pid != NULL) {
    char buffer[MAX_PATH_LEN] = {0};
    char *exec_path = get_module_path(buffer, sizeof(buffer), atoi(fc->pid));
    //LOGGER("exec_path : [%s], allow : [%s]", exec_path, fc->file_path);
    if (exec_path == NULL) {
      LOGGER("get_exec_from_pid failed. pid : [%s]", fc->pid);
      return 0;
    }

    if (strcmp(exec_path, fc->file_path) != 0) {
      LOGGER("check_exec_path failed. exec_path : [%s], allow : [%s]",
          exec_path, fc->file_path);
      return 0;
    }

    if (fc->sub_file != NULL) {
      char *script_path = get_module_script(
          buffer, sizeof(buffer), atoi(fc->pid));
      if (script_path == NULL) {
        LOGGER("get script_path failed. pid : [%s]", fc->pid);
        return 0;
      }
      LOGGER("script_path : %s\n", script_path);
      if (strcmp(script_path, fc->sub_file) != 0) {
        LOGGER("check_script_path failed. script_path : [%s], allow : [%s]",
               script_path, fc->sub_file);
        return 0;
      }
    }
  }

  if (fc->file_md5 != NULL) {
    char *pmd5 = get_file_md5(fc->file_path, md5buffer);
    if (pmd5 == NULL) {
      LOGGER("get_file_md5 failed. file : [%s]", fc->file_path);
      return 0;
    }

    if (strcmp(pmd5, fc->file_md5) != 0) {
      LOGGER("check_file_md5 failed. file : [%s], md5 : [%s], allow : [%s]",
             fc->file_path, pmd5, fc->file_md5);
      return 0;
    }
  }

  if (fc->sub_file != NULL && fc->sub_file_md5 != NULL) {
    char *pmd5 = get_file_md5(fc->sub_file, md5buffer);
    if (pmd5 == NULL) {
      LOGGER("get script_md5 failed. script : [%s]", fc->sub_file);
      return 0;
    }

    if (strcmp(pmd5, fc->sub_file_md5) != 0) {
      LOGGER("check_script_md5 failed. file : [%s], md5 : [%s], allow : [%s]",
             fc->sub_file, pmd5, fc->sub_file_md5);
      return 0;
    }
  }

  return 1;
}
// }}}

// {{{ FileMapStu
// 文件映射结构
// src_file:des_file:transform_lib:allow_exec1:allow_exe2......
typedef struct FileMapStu {
  FileCheckStu *src_file;
  char *des_file;
  char *des_path_file;
  get_buffer_size_t get_size_proc;
  transform_t transform_proc;
  VectorStu *allow_exec;
  MyfsBuffer *des_buffer;
} FileMapStu;

static void
file_map_stu_clear(FileMapStu *pstu, void *arg) {
  if (pstu == NULL) {
    return;
  }

  if (pstu->src_file != NULL) {
    file_check_stu_clear(pstu->src_file, NULL);
    free(pstu->src_file);
    pstu->src_file = NULL;
  }
  TRY_FREE_PROC(pstu->des_file);
  TRY_FREE_PROC(pstu->des_path_file);
  TRY_FREE_PROC(pstu->des_buffer);
  vector_clear(&pstu->allow_exec, (vector_do_proc)file_check_stu_clear, arg);
}

static VectorStu *s_file_maps = NULL;
static void
clear_all_file_map_stu(VectorStu **file_maps) {
  vector_clear(file_maps, (vector_do_proc)file_map_stu_clear, NULL);
}

static void
append_file_map(VectorStu **pfile_maps, const char *c) {
  // src_file:des_file:transform_lib:allow_exec1:allow_exe2......
  FileMapStu stu_file_map;
  FileCheckStu stu_file_check;
  memset((void *)&stu_file_map, 0, sizeof(stu_file_map));
  memset((void *)&stu_file_check, 0, sizeof(stu_file_check));

  const char *pstr = c;
  // 1,取src_file
  char *psrc_file = split_string_dup(pstr, ':', &pstr);
  if (psrc_file == NULL || *psrc_file == '0') {
    file_map_stu_clear(&stu_file_map, NULL);
    free(psrc_file);
    return;
  }
  cmd_to_file_check_stu(psrc_file, &stu_file_check);
  stu_file_map.src_file = (FileCheckStu *)malloc(sizeof(FileCheckStu));
  *stu_file_map.src_file = stu_file_check;
  memset((void *)&stu_file_check, 0, sizeof(stu_file_check));

  free(psrc_file);

  // 2,取des_file
  char *pdes_file = split_string_dup(pstr, ':', &pstr);
  if (pdes_file == NULL || *pdes_file == '\0') {
    file_map_stu_clear(&stu_file_map, NULL);
    return;
  } else {
    char *pdes_base = split_string_dup(pdes_file, '#', NULL);
    char *pdes_base_sub = split_string_dup(pdes_base, '?', NULL);
    free(pdes_base);

    if (strlen(pdes_base_sub) > 0) {
      stu_file_map.des_file = pdes_base_sub;
    } else {
      free(pdes_file);
      free(pdes_base_sub);
      return;
    }
  }

  stu_file_map.des_path_file =
      (char *)malloc(strlen(stu_file_map.des_file) + 2);
  stu_file_map.des_path_file[0] = '/';
  strcpy(stu_file_map.des_path_file + 1, stu_file_map.des_file);
  free(pdes_file);

  // 3,读取transform_lib
  char *ptransform_lib = split_string_dup(pstr, ':', &pstr);
  if (ptransform_lib == NULL || *ptransform_lib == '\0') {
    stu_file_map.get_size_proc = s_default_get_buffer_size_proc;
    stu_file_map.transform_proc = s_default_transform_proc;
  } else {
    cmd_to_file_check_stu(ptransform_lib, &stu_file_check);
    if (!do_file_check(&stu_file_check, 1, 0)) {
      LOGGER("not allow lib. lib : [%s], md5 : [%s]",
             stu_file_check.file_path,
             stu_file_check.file_md5);

      file_check_stu_clear(&stu_file_check, NULL);
      file_map_stu_clear(&stu_file_map, NULL);
      free(ptransform_lib);
      return;
    }

    TransformLibStu *plib = append_transform_lib(
        &s_transform_libs, stu_file_check.file_path);
    if (plib == NULL) {
      LOGGER("load lib failed. lib : [%s]", stu_file_check.file_path);

      file_check_stu_clear(&stu_file_check, NULL);
      file_map_stu_clear(&stu_file_map, NULL);
      free(ptransform_lib);
      return;
    }

    stu_file_map.get_size_proc = plib->get_size_proc;
    stu_file_map.transform_proc = plib->transform_proc;
  }

  file_check_stu_clear(&stu_file_check, NULL);
  free(ptransform_lib);

  // 4,读取allow_execs
  while (pstr != NULL) {
    char *pallow_exec = split_string_dup(pstr, ':', &pstr);
    if (*pallow_exec != '\0') {
      cmd_to_file_check_stu(pallow_exec, &stu_file_check);
      vector_push_back(&stu_file_map.allow_exec,
                       (const void *)&stu_file_check,
                       sizeof(FileCheckStu),
                       NULL,
                       NULL);
      memset((void *)&stu_file_check, 0, sizeof(stu_file_check));
    }

    free(pallow_exec);
  }

  vector_push_back(pfile_maps,
                   (const void *)&stu_file_map,
                   sizeof(stu_file_map),
                   NULL,
                   NULL);
}
// }}}

static VectorStu *s_allow_execs = NULL;  // 允许读取数据的可执行程序（全局）
static VectorStu *s_allow_exec_cmds = NULL;  // 允许读取数据的可执行程序命令行
static VectorStu *s_file_map_cmds = NULL;  // 文件映射命令行
char *s_transform_lib = NULL;  // 转换函数的so路径
FileCheckStu *s_watch_pid = NULL;
char *s_des_path = NULL;  // 挂载到的目录
char *s_log_file = NULL;  // 日志文件

__attribute__((constructor))void __fuse_test__init__(void) {
  get_module_path(s_cur_module_path, sizeof(s_cur_module_path), 0);
  dirname(s_cur_module_path);
  getcwd(s_cur_work_path, sizeof(s_cur_work_path));
}

__attribute__((destructor))void __fuse_test__uninit__(void) {
  if (log_fp != NULL) {
    fclose(log_fp);
  }

  vector_clear(&s_file_map_cmds, NULL, NULL);
  vector_clear(&s_allow_exec_cmds, NULL, NULL);

  TRY_FREE_PROC(s_transform_lib);
  TRY_FREE_PROC(s_des_path);
  TRY_FREE_PROC(s_log_file);

  if (s_watch_pid != NULL) {
    file_check_stu_clear(s_watch_pid, NULL);
    free(s_watch_pid);
  }

  vector_clear(&s_allow_execs, (vector_do_proc)file_check_stu_clear, NULL);
  clear_all_file_map_stu(&s_file_maps);
  clear_all_transform_lib_stu(&s_transform_libs);
}

__attribute__((format(printf, 4, 5))) static void
logger(const char *file,
       unsigned int l,
       const char *fun,
       const char *fmt, ...) {
  if (log_fp == NULL && log_output == 0) {
    return;
  }

  struct tm tm;
  struct timeval tv;
  gettimeofday(&tv, NULL);
  localtime_r(&tv.tv_sec, &tm);

  char buf[4096] = {0};
  va_list ap;
  va_start(ap, fmt);
  int n = snprintf(
      buf, sizeof(buf),
      "%02d-%02d %02d:%02d:%02d.%06ld <%s:%u->%s>:",
      tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec,
      file, l, fun);
  n += vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
  va_end(ap);

  if (n >= sizeof(buf) - 1) {
    buf[n - 1] = '\n';
  } else {
    buf[n] = '\n';
    n++;
  }

  if (log_fp != NULL) {
    fwrite(buf, n, 1, log_fp);
    fflush(log_fp);
  }
  if (log_output != 0) {
    printf("%s", buf);
  }
}

/*[[ maybe_unused ]] */static void
get_arg_proc(char **arg, char **saveptr) {
  if (arg == NULL) {
    return;
  }

  char *token = strtok_r(NULL, "=", saveptr);
  int l = 0;
  if (token == NULL || (l = strlen(token)) == 0) {
    return;
  }

  *arg = strdup(token);
  return;
}

/*[[ maybe_unused ]] */__attribute__(( unused )) static void
get_path_arg_proc(char **arg, char **saveptr) {
  if (arg == NULL) {
    return;
  }

  char *token = strtok_r(NULL, "=", saveptr);
  int l = 0;
  if (token == NULL || (l = strlen(token)) == 0) {
    return;
  }

  char buf[MAX_PATH_LEN] = {0};
  get_absolute_path(token, buf, sizeof(buf), 0);
  *arg = strdup(buf);
  return;
}

/*[[ maybe_unused ]] */static void
get_varg_proc(struct VectorStu **args, char **saveptr) {
  if (args == NULL) {
    return;
  }
  char *token = strtok_r(NULL, "=", saveptr);
  int l = 0;
  if (token == NULL || (l = strlen(token)) == 0) {
    return;
  }

  vector_push_back(args, token, strlen(token) + 1, NULL, NULL);
  return;
}

/*[[ maybe_unused ]] */static void
get_path_varg_proc(struct VectorStu **args, char **saveptr) {
  if (args == NULL) {
    return;
  }
  char *token = strtok_r(NULL, "=", saveptr);
  int l = 0;
  if (token == NULL || (l = strlen(token)) == 0) {
    return;
  }

  char buf[MAX_PATH_LEN] = {0};
  get_absolute_path(token, buf, sizeof(buf), 0);
  vector_push_back(args, buf, strlen(buf) + 1, NULL, NULL);
  return;
}

static void *
watch_proc(void *unuse__) {
  if (s_watch_pid->pid != NULL) {
    do {
      usleep(300000);
    } while (do_file_check(s_watch_pid, 0, 0));
  }

  kill(getpid(), SIGTERM);
  return NULL;
}

static int
check_allow_proc(FileCheckStu *pstu, char *pid) {
  FileCheckStu stu = *pstu;
  stu.pid = pid;
  return do_file_check(&stu, 1, stu.sub_file == NULL ? 0 : 1) ? 1 : 0;
}

static int
check_allow(const char *path) {
  pid_t pid = fuse_get_context()->pid;
  char buffer_pid[16] = {0};
  snprintf(buffer_pid, sizeof(buffer_pid), "%d", pid);

  // 测试全局允许
  if (s_allow_execs != NULL) {
    void *pret = vector_for_each(s_allow_execs,
                                 (vector_do_proc)check_allow_proc,
                                 (void *)buffer_pid);
    if (pret != NULL) {
      return 1;
    }
  }

  // 目标文件级校验
  if (s_file_maps != NULL) {
    for (int i = 0; i < s_file_maps->n; i++) {
      FileMapStu *pfile = (FileMapStu *)s_file_maps->d[i];
      if (strcmp(pfile->des_path_file, path) != 0) {
        continue;
      }

      void *pret = vector_for_each(pfile->allow_exec,
                                   (vector_do_proc)check_allow_proc,
                                   (void *)buffer_pid);
      if (pret != NULL) {
        return 1;
      }
    }
  }

  return 0;
}

static int
myfs_getattr(const char *path,
             struct stat *stbuf,
             struct fuse_file_info *unuse__) {
  int res = 0;

  memset(stbuf, 0, sizeof(struct stat));

  if (strcmp(path, "/") == 0) {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 1;
  } else if (s_file_maps == NULL) {
    res = -ENOENT;
  } else {
    res = -ENOENT;
    for (int i = 0; i < s_file_maps->n; i++) {
      FileMapStu *pstu = (FileMapStu *)s_file_maps->d[i];
      if (strcmp(path, pstu->des_path_file) == 0) {
        stbuf->st_mode = S_IFREG | 0444;
        stbuf->st_nlink = 1;
        stbuf->st_size = pstu->des_buffer->n;
        res = 0;
        break;
      }
    }
  }

  return res;
}

static int
myfs_readdir(const char *path,
             void *buf,
             fuse_fill_dir_t filler,
             off_t offset,
             struct fuse_file_info *fi,
             enum fuse_readdir_flags unuse__) {
  (void)offset;
  (void)fi;

  if (strcmp(path, "/") != 0) {
    return -ENOENT;
  }

  //filler(buf, ".", NULL, 0);
  //filler(buf, "..", NULL, 0);
  if (s_file_maps != NULL) {
    for (int i = 0; i < s_file_maps->n; i++) {
      FileMapStu *pstu = (FileMapStu *)s_file_maps->d[i];
      filler(buf, pstu->des_file, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
    }
  }

  return 0;
}

static int
myfs_open(const char *path, struct fuse_file_info *fi) {
  if (!check_allow(path)) {
    LOGGER("check_allow failed.");
    return -EACCES;
  }

  if ((fi->flags & 3) != O_RDONLY) {  // 权限
    return -EACCES;
  }

  if (s_file_maps != NULL) {
    for (int i = 0; i < s_file_maps->n; i++) {
      FileMapStu *pstu = (FileMapStu *)s_file_maps->d[i];
      if (strcmp(path, pstu->des_path_file) == 0) {
        return 0;
      }
    }
  }

  return -ENOENT;
}

static int
myfs_read(const char *path, char *buf, size_t size,
          off_t offset, struct fuse_file_info *unuse__) {
  FileMapStu *pstu = NULL;
  if (s_file_maps != NULL) {
    for (int i = 0; i < s_file_maps->n; i++) {
      FileMapStu *pstu_tmp = (FileMapStu *)s_file_maps->d[i];
      if (strcmp(path, pstu_tmp->des_path_file) == 0) {
        pstu = pstu_tmp;
        break;
      }
    }
  }

  if (pstu == NULL) {
    return -ENOENT;
  }

  if (offset < pstu->des_buffer->n) {
    if (offset + size > pstu->des_buffer->n) {
      size = pstu->des_buffer->n - offset;
    }
    memcpy(buf, pstu->des_buffer->d + offset, size);
  } else {
    size = 0;
  }

  return size;
}

static struct fuse_operations myfs_oper = {
  .getattr    = myfs_getattr,
  .readdir    = myfs_readdir,
  .open       = myfs_open,
  .read       = myfs_read,
};

int main(int argc, char *argv[]) {
  int debug = 0;

  for (int i = 1; i < argc; i++) {
    char *saveptr, *tokenk;
    tokenk = strtok_r(argv[i], "=", &saveptr);
    if (strcmp(tokenk, "--allow_exec") == 0) {
      get_path_varg_proc(&s_allow_exec_cmds, &saveptr);
    } else if (strcmp(tokenk, "--des_path") == 0) {
      get_arg_proc(&s_des_path, &saveptr);
    } else if (strcmp(tokenk, "--transform_lib") == 0) {
      get_arg_proc(&s_transform_lib, &saveptr);
    } else if (strcmp(tokenk, "--watch_pid") == 0) {
      char *pcmd = NULL;
      get_arg_proc(&pcmd, &saveptr);
      FileCheckStu stu;
      memset((void *)&stu, 0, sizeof(stu));
      cmd_to_file_check_stu(pcmd, &stu);
      if (stu.pid != NULL) {
        s_watch_pid = (FileCheckStu *)malloc(sizeof(FileCheckStu));
        *s_watch_pid = stu;
      } else {
        file_check_stu_clear(&stu, NULL);
      }

      free(pcmd);
    } else if (strcmp(tokenk, "--log_file") == 0) {
      get_arg_proc(&s_log_file, &saveptr);
    } else if (strcmp(tokenk, "--file_mapping") == 0) {
      get_varg_proc(&s_file_map_cmds, &saveptr);
    } else if (strcmp(tokenk, "--debug") == 0) {
      debug = 1;
    } else if (strcmp(tokenk, "--log_output") == 0) {
      log_output = 1;
    }
  }

#define CHECK_MUST_ARGS(n, e) do {  \
    if (n == NULL) {                \
      LOGGER(e);                    \
      exit(1);                      \
    }                               \
  } while (0)

  CHECK_MUST_ARGS(s_des_path, "unknow des_path. --des_path=...");

#undef CHECK_MUST_ARGS

  // 打开日志
  if (s_log_file != NULL) {
    log_fp = fopen(s_log_file, "a+");
  }

  // 全局允许的exec
  if (s_allow_exec_cmds != NULL) {
    for (int i = 0; i < s_allow_exec_cmds->n; i++) {
      FileCheckStu stu_file_check;
      memset((void *)&stu_file_check, 0, sizeof(stu_file_check));
      cmd_to_file_check_stu(s_allow_exec_cmds->d[i], &stu_file_check);
      vector_push_back(&s_allow_execs,
                       (const void *)&stu_file_check,
                       sizeof(FileCheckStu),
                       NULL,
                       NULL);
    }
  }

  // 修正的默认数据转换函数
  if (s_transform_lib != NULL) {  // 修改 default_transform
    FileCheckStu stu_file_check;
    int check_success = 0;
    memset((void *)&stu_file_check, 0, sizeof(stu_file_check));

    cmd_to_file_check_stu(s_transform_lib, &stu_file_check);
    do {
      if (!do_file_check(&stu_file_check, 1, 0)) {
        LOGGER("not allow lib. lib : [%s], md5 : [%s]",
            stu_file_check.file_path,
            stu_file_check.file_md5);
        break;
      }

      TransformLibStu *plib = append_transform_lib(&s_transform_libs,
                                                   stu_file_check.file_path);
      if (plib == NULL) {
        LOGGER("append_transform_lib failed. lib : [%s]",
               stu_file_check.file_path);
        break;
      }

      s_default_transform_proc = plib->transform_proc;
      s_default_get_buffer_size_proc = plib->get_size_proc;

      check_success = 1;
    } while (0);

    if (!check_success) {
      LOGGER("dlopen [%s] failed.", stu_file_check.file_path);
    }

    file_check_stu_clear(&stu_file_check, NULL);
  }

  // 初始化文件映射
  if (s_file_map_cmds != NULL) {
    for (int i = 0; i < s_file_map_cmds->n; i++) {
      append_file_map(&s_file_maps, s_file_map_cmds->d[i]);
    }
  }

  if (s_file_maps != NULL) {
    for (int i = 0; i < s_file_maps->n; i++) {
      // 读取原始数据
      FileMapStu *pstu = (FileMapStu *)s_file_maps->d[i];
      if (!do_file_check(pstu->src_file, 0, 0)) {
        LOGGER("check input file <%s> failed.", pstu->src_file->file_path);
        continue;
      }

      FILE *fp = fopen(pstu->src_file->file_path, "rb");
      if (fp == NULL) {
        LOGGER("open input file <%s> failed.", pstu->src_file->file_path);
        continue;
      }

      fseek(fp, 0, SEEK_END);
      unsigned long data_len = ftell(fp);
      fseek(fp, 0, SEEK_SET);
      MyfsBuffer *src_buff =
            (MyfsBuffer *)malloc(sizeof(MyfsBuffer) + data_len);
      src_buff->n = data_len;
      fread(src_buff->d, data_len, 1, fp);
      fclose(fp);

      // 数据转换
      data_len = pstu->get_size_proc(src_buff->d, src_buff->n, argc, argv);
      pstu->des_buffer = (MyfsBuffer *)malloc(sizeof(MyfsBuffer) + data_len);
      pstu->des_buffer->n = data_len;
      if (pstu->transform_proc(src_buff->d,
                               src_buff->n,
                               pstu->des_buffer->d,
                               pstu->des_buffer->n,
                               argc,
                               argv) != 0) {
        LOGGER("transform_proc failed.");
        continue;
      }

      free(src_buff);
      src_buff = NULL;
    }
  }

  // 监视父进程
  if (s_watch_pid != NULL) {
    pthread_t h;
    pthread_create(&h, NULL, watch_proc, NULL);
  }

  char *fuse_args[] = {
    argv[0],
    "-f",
    s_des_path,
    "-o",
    "allow_other",
    "-o",
    "auto_unmount",

    "-d",  // -d 放最后，用于调整debug参数
  };

  // 如果开启debug，就让最后一个-d参数生效
  int ret = fuse_main(
      sizeof(fuse_args) / sizeof(fuse_args[0]) - (debug ? 0 : 1),
      fuse_args,
      &myfs_oper,
      NULL);
  return ret;
}
