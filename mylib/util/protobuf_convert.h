#pragma once

#ifdef __cplusplus
#include <string>

namespace google {
namespace protobuf {
  class Message;
} // namespace protobuf
} // namespace google

namespace Json {
  class Value;
} // namespace Json

namespace miku {
bool json_to_protobuf(const std::string &j, google::protobuf::Message *m);
bool protobuf_to_json(const google::protobuf::Message &m,
                      std::string *j,
                      bool for_response = false);
}

extern "C" {
#endif // __cplusplus




#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus

