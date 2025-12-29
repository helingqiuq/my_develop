#pragma once
#include <sstream>

#include <zlib.h>
#include <stdint.h>

namespace miku {
#define PROC_DEFINE(proc)                             \
int32_t proc(std::istream *src,                       \
             std::ostream *des);                      \
int32_t proc##_s2s(const std::string &src,            \
                std::string *des);                    \
int32_t proc##_f2f(const std::string &src,            \
                const std::string &des);              \
int32_t proc##_f2s(const std::string &src,            \
                std::string *des);                    \
int32_t proc##_s2f(const std::string &src,            \
                const std::string &des);

PROC_DEFINE(def)
PROC_DEFINE(def2)
PROC_DEFINE(inf)
PROC_DEFINE(inf2)

#undef PROC_DEFINE
}
