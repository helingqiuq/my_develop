#include "request_map.h"

CLIENT_HELP_GRPC_CLIENT_IMPL(Login, miku::login, interface, RequestMap)
RequestMap(HTTP_HELP_FUNCATION_IMPL, Login, miku::login, interface)
