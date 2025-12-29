package(default_visibility = ["//visibility:public"])

cc_binary(
  name = "test_efile",
  srcs = ["test_efile.cc"],
  copts = ["-Iexternal/third_party/include"],
  linkopts = ["-ldl", "-lpthread", "-lz"],
  deps = [
    "//efile:efile",
    "//util:util",
    "@third_party//:third_party",
  ],
)

cc_binary(
  name = "test_efile_mapping",
  srcs = ["test_efile_mapping.cc"],
  copts = ["-Iexternal/third_party/include"],
  linkopts = ["-ldl", "-lpthread", "-lz"],
  deps = [
    "//efile:efile",
    "//efile:libefile_mapping",
    "//util:util",
    "@third_party//:third_party",
  ],
)

cc_binary(
  name = "efile_mapping_tool",
  srcs = ["efile_mapping_tool.cc"],
  copts = ["-Iexternal/third_party/include"],
  linkopts = ["-ldl", "-lpthread", "-lz"],
  deps = [
    "//efile:efile",
    "//efile:libefile_mapping",
    "//util:util",
    "@third_party//:third_party",
  ],
)

cc_binary(
  name = "test_util",
  srcs = ["test_util.cc"],
  copts = ["-Iexternal/third_party/include"],
  linkopts = ["-ldl", "-lpthread", "-lz"],
  deps = [
    "//util:util",
    "@third_party//:third_party",
  ],
)
