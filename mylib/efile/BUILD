package(default_visibility = ["//visibility:public"])
filegroup(
  name = "all_srcs",
  srcs = glob(["**/*.cc", "**/*.c"]),
)

filegroup(
  name = "all_header",
  srcs = glob(["**/*.h"]),
)

cc_library(
  name = "efile",
  hdrs = ["efile.h"],
  srcs = ["efile.cc"],
  copts = ["-Iexternal/third_party/include"],
  linkstatic = 1,
  deps = [
    "@third_party//:third_party",
    "//encrypt_help:encrypt_help",
    "//util:util",
  ],
)

cc_library(
  name = "libefile_mapping",
  hdrs = ["efile.h", "efile_mapping.h"],
  srcs = ["efile_mapping.cc"],
  copts = ["-Iexternal/third_party/include"],
  linkstatic = 1,
  deps = [
    "@third_party//:third_party",
    "//encrypt_help:encrypt_help",
    "//util:util",
    ":efile",
    ":libprocess_auth"
  ],
)

cc_library(
  name = "libprocess_auth",
  hdrs = ["process_auth.h"],
  srcs = ["process_auth.cc"],
  copts = ["-Iexternal/third_party/include"],
  linkstatic = 1,
  deps = [
    "//util:util",
    "//encrypt_help:encrypt_help",
  ],
)
