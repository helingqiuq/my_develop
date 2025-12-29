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
  name = "encrypt_help",
  hdrs = [":all_header"],
  srcs = [":all_srcs"],
  copts = ["-Iexternal/third_party/include"],
  linkstatic = 1,
  deps = [
    "@third_party//:third_party",
  ],
)

