#pragma once

#include "middle/http_service_help.h"
#include "middle/client_help.h"
#include "proto/login.grpc.pb.h"

#define RequestMap(XX, CN, PN, SV)            \
  XX(CN, PN, SV, Register, register)          \
  XX(CN, PN, SV, Login, login)                \
  XX(CN, PN, SV, Update, update)              \
  XX(CN, PN, SV, Freeze, freeze)              \
  XX(CN, PN, SV, Unfreeze, unfreeze)          \
  XX(CN, PN, SV, Cancel, cancel)              \
  XX(CN, PN, SV, Find, find)

RequestMap(HTTP_HELP_FUNCATION_DECLARE, Login, miku::login, interface)
CLIENT_HELP_GRPC_CLIENT_DECLARE(Login, miku::login, interface, RequestMap)
