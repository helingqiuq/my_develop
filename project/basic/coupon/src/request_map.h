#pragma once

#include "middle/http_service_help.h"
#include "middle/client_help.h"
#include "proto/coupon.grpc.pb.h"

#define RequestMap(XX, CN, PN, SV)            \
  XX(CN, PN, SV, Create, create)              \
  XX(CN, PN, SV, Invocation, invocation)      \
  XX(CN, PN, SV, Exchange, exchange)          \
  XX(CN, PN, SV, Cancel, cancel)              \
  XX(CN, PN, SV, Expire, expire)              \
  XX(CN, PN, SV, Find, find)

RequestMap(HTTP_HELP_FUNCATION_DECLARE, Coupon, miku::coupon, interface)
CLIENT_HELP_GRPC_CLIENT_DECLARE(Coupon, miku::coupon, interface, RequestMap)
