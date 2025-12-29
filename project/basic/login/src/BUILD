cc_binary(
  name = "server",
  linkopts = ["-ldl", "-lpthread", "-lz"],
  deps = [
    ":libserver",
  ],
)

filegroup (
  name = "all_srcs",
  srcs = glob(["**/*.cc"]),
)

filegroup (
  name = "all_hdrs",
  srcs = glob(["**/*.h"]),
)

cc_library(
  name = "libserver",
  hdrs = [":all_hdrs"],
  srcs = [":all_srcs"],
  copts = ["-Iexternal/third_party/include"],
  deps = [
    "//proto:liblogin_proto",
    "@mylib//middle:middle",
  ],
)
