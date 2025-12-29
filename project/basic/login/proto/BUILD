package(default_visibility = ["//visibility:public"])

cc_library(
  name = "liblogin_proto",
  srcs = [":login_proto"],
  copts = ["-Iexternal/third_party/include"],
  deps = [
    "@third_party//:third_party",
  ],
)

load("@third_party//mybzl:my_proto.bzl", "my_proto")
load("@third_party//mybzl:my_proto.bzl", "my_grpc_proto")

my_grpc_proto(
  name = "login_proto",
  srcs = ["login.proto"],
)
