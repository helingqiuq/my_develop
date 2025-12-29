#include "z_help.h"

#include <fstream>

#define CHUNK (1 << 18)

using DEF_INIT_PROC = int32_t (*)(z_stream *strm);

static int32_t
def_init_proc(z_stream *strm) {
  return deflateInit(strm, Z_BEST_COMPRESSION);
}

static int32_t
def_init2_proc(z_stream *strm) {
  return deflateInit2(strm, Z_BEST_COMPRESSION, Z_DEFLATED,
      MAX_WBITS + 16, MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY);
}

static int32_t
def_basic(std::istream *src,
          std::ostream *des,
          DEF_INIT_PROC init_proc) {
  z_stream strm;
  uint8_t in[CHUNK];
  uint8_t out[CHUNK];
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  int32_t flush;
  uint32_t have;

  int32_t ret = init_proc(&strm);
  if (ret != Z_OK) {
    return ret;
  }

  do {
    strm.avail_in = src->readsome(reinterpret_cast<char *>(in), CHUNK);
    if (src->bad()) {
      deflateEnd(&strm);
      return Z_ERRNO;
    }

    flush = (strm.avail_in < CHUNK) ? Z_FINISH : Z_NO_FLUSH;
    strm.next_in = in;
    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = deflate(&strm, flush);
      if (ret != Z_OK && ret != Z_STREAM_END) {
        deflateEnd(&strm);
        return ret;
      }
      have = CHUNK - strm.avail_out;
      des->write(reinterpret_cast<char *>(out), have);
    } while (strm.avail_out == 0);
  } while (flush != Z_FINISH);

  return Z_OK;
}

using INF_INIT_PROC = int32_t (*)(z_stream *strm);
static int32_t
inf_init_proc(z_stream *strm) {
  return inflateInit(strm);
}

static int32_t
inf_init2_proc(z_stream *strm) {
  return inflateInit2(strm, MAX_WBITS + 16);
}

static int32_t
inf_basic(std::istream *src,
          std::ostream *des,
          INF_INIT_PROC init_proc) {
  int32_t ret;
  uint32_t have;
  z_stream strm;
  uint8_t in[CHUNK];
  uint8_t out[CHUNK];

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  ret = init_proc(&strm);
  if (ret != Z_OK) {
    return ret;
  }

  do {
    strm.avail_in = src->readsome(reinterpret_cast<char *>(in), CHUNK);
    if (src->bad()) {
      inflateEnd(&strm);
      return Z_ERRNO;
    }

    if (strm.avail_in == 0) {
      break;
    }

    strm.next_in = in;

    do {
      strm.avail_out = CHUNK;
      strm.next_out = out;
      ret = inflate(&strm, Z_NO_FLUSH);
      switch (ret) {
       case Z_NEED_DICT:
        ret = Z_DATA_ERROR;     /* and fall through */
       case Z_DATA_ERROR:
       case Z_MEM_ERROR:
        inflateEnd(&strm);
        return ret;
      }
      have = CHUNK - strm.avail_out;
      des->write(reinterpret_cast<char *>(out), have);
    } while (strm.avail_out == 0);
  } while (ret != Z_STREAM_END);

  /* clean up and return */
  inflateEnd(&strm);
  return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}


namespace miku {

#define PROC_DECLARE(proc)                                                    \
int32_t proc##_s2s(const std::string &src,                                    \
                   std::string *des) {                                        \
  std::istringstream is(src, std::ios::binary | std::ios::in);                \
  std::stringstream ss;                                                       \
  int32_t ret = proc(&is, &ss);                                               \
  *des = ss.str();                                                            \
  return ret;                                                                 \
}                                                                             \
int32_t proc##_f2f(const std::string &src,                                    \
                   const std::string &des) {                                  \
  std::ifstream ifile(src, std::ios::binary | std::ios::in);                  \
  if (!ifile.is_open()) {                                                     \
    return Z_ERRNO;                                                           \
  }                                                                           \
  std::ofstream ofile(des, std::ios::binary | std::ios::in | std::ios::trunc);\
  if (!ofile.is_open()) {                                                     \
    ifile.close();                                                            \
    return Z_ERRNO;                                                           \
  }                                                                           \
                                                                              \
  int32_t ret = proc(&ifile, &ofile);                                         \
  ifile.close();                                                              \
  ofile.close();                                                              \
  return ret;                                                                 \
}                                                                             \
int32_t proc##_f2s(const std::string &src,                                    \
                std::string *des) {                                           \
  std::ifstream ifile(src, std::ios::binary | std::ios::in);                  \
  if (!ifile.is_open()) {                                                     \
    return Z_ERRNO;                                                           \
  }                                                                           \
  std::stringstream ss;                                                       \
  int32_t ret = proc(&ifile, &ss);                                            \
  *des = ss.str();                                                            \
  return ret;                                                                 \
}                                                                             \
int32_t proc##_s2f(const std::string &src,                                    \
                const std::string &des) {                                     \
  std::istringstream is(src, std::ios::binary | std::ios::in);                \
  std::ofstream ofile(des, std::ios::binary | std::ios::in | std::ios::trunc);\
  if (!ofile.is_open()) {                                                     \
    ofile.close();                                                            \
    return Z_ERRNO;                                                           \
  }                                                                           \
                                                                              \
  int32_t ret = proc(&is, &ofile);                                            \
  ofile.close();                                                              \
  return ret;                                                                 \
}


int32_t def(std::istream *src, std::ostream *des) {
  return def_basic(src, des, def_init_proc);
}
PROC_DECLARE(def)

int32_t def2(std::istream *src, std::ostream *des) {
  return def_basic(src, des, def_init2_proc);
}
PROC_DECLARE(def2)

int32_t inf(std::istream *src, std::ostream *des) {
  return inf_basic(src, des, inf_init_proc);
}
PROC_DECLARE(inf)

int32_t inf2(std::istream *src, std::ostream *des) {
  return inf_basic(src, des, inf_init2_proc);
}
PROC_DECLARE(inf2)

#undef PROC_DECLARE
}
