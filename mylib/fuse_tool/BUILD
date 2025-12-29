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
  name = "fuse_tool_a",
  hdrs = [":all_header"],
  srcs = [":all_srcs"],
  copts = ["-Iexternal/third_party/include"],
  linkstatic = 1,
  deps = [
    "@third_party//:third_party",
    "//encrypt_help:encrypt_help",
  ],
)

cc_binary(
  name = "fuse_tool",
  linkopts = ["-ldl", "-lpthread"],
  deps = [
    ":fuse_tool_a",
    "//encrypt_help:encrypt_help",
    "@third_party//:third_party",
  ],
)

