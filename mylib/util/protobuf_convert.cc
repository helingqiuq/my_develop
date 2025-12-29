#include "protobuf_convert.h"

#include "google/protobuf/util/json_util.h"

namespace miku {
#if 0
static bool json_to_protobuf_proc(const Json::Value &v,
                                  google::protobuf::Message *m);
static bool protobuf_to_json_proc(const google::protobuf::Message &m,
                                  std::string *j);

static void
format_json_string(const std::string &s, std::string *j) {
  const char *p = s.c_str();
  while (*p != '\0') {
    char ch = *p++;
    switch (ch) {
     case 0x22: j->append("\\\""); continue;
     case 0x5C: j->append("\\\\"); continue;
     case 0x2F: j->append("\\/");  continue;
     case 0x08: j->append("\\b");  continue;
     case 0x0C: j->append("\\f");  continue;
     case 0x0A: j->append("\\n");  continue;
     case 0x0D: j->append("\\r");  continue;
     case 0x09: j->append("\\t");  continue;
     default:
      {
        char buf[2] = {0};
        buf[0] = ch;
        j->append(buf);
        continue;
      }
    }
  }
}

static bool
append_string(const std::string &s, std::string *j) {
  j->append("\"");
  format_json_string(s, j);
  j->append("\"");
  return true;
}  // function append_string

static bool
append_bytes(const std::string &s, std::string *j) {
  std::string e;
  int buflen = (s.length() + 2) / 3 * 4 + 1;
  char *base64_str = (char *)malloc(buflen);
  if (base64_str == nullptr) {
    return false;
  }

  if (miku_b64_encode(
        (const unsigned char *)s.c_str(),
        s.length(),
        base64_str,
        buflen) < 0) {
    free(base64_str);
    return false;
  }

  base64_str[buflen - 1] = '\0';

  j->append("\"");
  j->append(base64_str);
  j->append("\"");

  free(base64_str);
  return true;
} // function append_bytes

static bool
decode_bytes(const std::string &s, std::string *j) {
  int buflen = s.length() / 4 * 3 + 1;
  char *buffer = (char *)malloc(buflen);
  if (buffer == nullptr) {
    return false;
  }
  int ret = miku_b64_decode(s.c_str(), s.length(), (unsigned char *)buffer, buflen);
  if (ret < 0) {
    free(buffer);
    return false;
  }
  buffer[ret] = '\0';
  *j = std::string(buffer);
  free(buffer);
  return true;
} // function decode_bytes

__attribute__((visibility ("default")))
bool json_to_protobuf(const std::string &j, google::protobuf::Message *m) {
  Json::Value v;
  Json::CharReaderBuilder JReader;
  JReader["collectComments"] = false;
  std::unique_ptr<Json::CharReader> r(JReader.newCharReader());
  std::string errs;

  if (!r->parse(j.c_str(), j.c_str() + j.length(), &v, &errs) ||
      !v.isObject()) {
    return false;
  }

  try {
    return json_to_protobuf_proc(v, m);
  } catch (const Json::Exception &) {
    return false;
  }
} // function json_to_protobuf

static bool
json_to_protobuf_proc(const Json::Value &v, google::protobuf::Message *m) {
  const google::protobuf::EnumValueDescriptor *ev;
  const google::protobuf::Reflection *r = m->GetReflection();
  const google::protobuf::Descriptor *d = m->GetDescriptor();

  if (!v.isObject()) {
    return false;
  }

  for (Json::Value::const_iterator p = v.begin(); p != v.end(); ++p) {
    const google::protobuf::FieldDescriptor *f = d->FindFieldByName(p.name());
    if (f == nullptr) {
      f = r->FindKnownExtensionByName(p.name());
      if (f == nullptr) {
        return false;
      }
    }

    if (f->is_repeated()) {
      if (!p->isArray()) {
        return false;
      }

      for (Json::Value::const_iterator q = p->begin();
          q != p->end();
          ++q) {
        switch (f->cpp_type()) {
         case google::protobuf::FieldDescriptor::CPPTYPE_ENUM:
          if (q->isInt()) {
            ev = f->enum_type()->FindValueByNumber(q->asInt());
            if (ev == nullptr) {
              return false;
            }
            r->AddEnum(m, f, ev);
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
          if (q->isDouble()) {
            r->AddFloat(m, f, q->asFloat());
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
          if (q->isDouble()) {
            r->AddDouble(m, f, q->asDouble());
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
          if (q->isInt()) {
            r->AddInt32(m, f, q->asInt());
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
          if (q->isInt64()) {
            r->AddInt64(m, f, q->asInt64());
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
          if (q->isUInt()) {
            r->AddUInt32(m, f, q->asUInt());
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
          if (q->isUInt64()) {
            r->AddUInt64(m, f, q->asUInt64());
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
          if (q->isBool()) {
            r->AddBool(m, f, q->asBool());
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
          if (q->isString()) {
            if (f->type() == google::protobuf::FieldDescriptor::TYPE_STRING) {
              r->AddString(m, f, q->asString());
            } else {
              std::string s;
              if (!decode_bytes(q->asString(), &s)) {
                return false;
              }

              r->AddString(m, f, s);
            }
          }
          break;

         case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
          if (!json_to_protobuf_proc(*q, r->AddMessage(m, f))) {
            return false;
          }
          break;
        };
      }
    } else {
      switch (f->cpp_type()) {
       case google::protobuf::FieldDescriptor::CPPTYPE_ENUM:
        if (p->isInt()) {
          ev = f->enum_type()->FindValueByNumber(p->asInt());
          if (ev == nullptr) {
            return false;
          }
          r->SetEnum(m, f, ev);
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
        if (p->isDouble()) {
          r->SetFloat(m, f, p->asFloat());
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
        if (p->isDouble()) {
          r->SetDouble(m, f, p->asDouble());
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
        if (p->isInt()) {
          r->SetInt32(m, f, p->asInt());
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
        if (p->isInt64()) {
          r->SetInt64(m, f, p->asInt64());
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
        if (p->isUInt()) {
          r->SetUInt32(m, f, p->asUInt());
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
        if (p->isUInt64()) {
          r->SetUInt64(m, f, p->asUInt64());
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
        if (p->isBool()) {
          r->SetBool(m, f, p->asBool());
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
        if (p->isString()) {
          if (f->type() ==
              google::protobuf::FieldDescriptor::TYPE_STRING) {
            r->SetString(m, f, p->asString());
          } else {
            std::string s;
            if (!decode_bytes(p->asString(), &s)) {
              return false;
            }

            r->SetString(m, f, s);
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
        if (!json_to_protobuf_proc(*p, r->MutableMessage(m, f))) {
          return false;
        }
        break;
      };
    }
  }

  return true;
} // function json_to_protobuf_proc

__attribute__((visibility ("default")))
bool protobuf_to_json(const google::protobuf::Message &m, std::string *j) {
  j->clear();
  return protobuf_to_json_proc(m, j);
} // function protobuf_to_json

static bool
protobuf_to_json_proc(const google::protobuf::Message &m, std::string *j) {
  std::vector<const google::protobuf::FieldDescriptor *> fields;
  const google::protobuf::Reflection *r = m.GetReflection();
  r->ListFields(m, &fields);
  const char *delim = "";
  const char *comma = "";
  char buffer[32];

  j->append("{");

  for (auto it = fields.begin(); it != fields.end(); ++it) {
    auto &f = *it;
    j->append(delim);
    delim = ",";
    if (f->is_extension()) {
      if (!append_string(f->full_name(), j)) {
        return false;
      }
    } else {
      if (!append_string(f->name(), j)) {
        return false;
      }
    }

    j->append(":");
    if (f->is_repeated()) {
      j->append("[");
      comma = "";
      switch (f->cpp_type()) {
       case google::protobuf::FieldDescriptor::CPPTYPE_ENUM:
       case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
        {
          //auto &int32_field = r->GetRepeatedField<int32_t>(m, f);
          auto int32_field = r->GetRepeatedFieldRef<int32_t>(m, f);
          for (auto it = int32_field.begin(); it != int32_field.end(); ++it) {
            snprintf(buffer, sizeof(buffer), "%s%d", comma, *it);
            j->append(buffer);
            comma = ",";
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
        {
          //auto &float_field = r->GetRepeatedField<float>(m, f);
          auto float_field = r->GetRepeatedFieldRef<float>(m, f);
          for (auto it = float_field.begin(); it != float_field.end(); ++it) {
            snprintf(buffer, sizeof(buffer), "%s%f", comma, *it);
            j->append(buffer);
            comma = ",";
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
        {
          //auto &double_field = r->GetRepeatedField<double>(m, f);
          auto double_field = r->GetRepeatedFieldRef<double>(m, f);
          for (auto it = double_field.begin(); it != double_field.end(); ++it) {
            snprintf(buffer, sizeof(buffer), "%s%lf", comma, *it);
            j->append(buffer);
            comma = ",";
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
        {
          //auto &int64_field = r->GetRepeatedField<int64_t>(m, f);
          auto int64_field = r->GetRepeatedFieldRef<int64_t>(m, f);
          for (auto it = int64_field.begin();
              it != int64_field.end();
              ++it) {
            snprintf(buffer, sizeof(buffer), "%s%lld", comma, (long long)*it);
            j->append(buffer);
            comma = ",";
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
        {
          //auto &uint32_field = r->GetRepeatedField<uint32_t>(m, f);
          auto uint32_field = r->GetRepeatedFieldRef<uint32_t>(m, f);
          for (auto it = uint32_field.begin();
              it != uint32_field.end();
              ++it) {
            snprintf(buffer, sizeof(buffer), "%s%u", comma, *it);
            j->append(buffer);
            comma = ",";
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
        {
          //auto &uint64_field = r->GetRepeatedField<uint64_t>(m, f);
          auto uint64_field = r->GetRepeatedFieldRef<uint64_t>(m, f);
          for (auto it = uint64_field.begin();
              it != uint64_field.end();
              ++it) {
            snprintf(buffer, sizeof(buffer), "%s%llu", comma, (unsigned long long)*it);
            j->append(buffer);
            comma = ",";
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
        {
          //auto &bool_field = r->GetRepeatedField<bool>(m, f);
          auto bool_field = r->GetRepeatedFieldRef<bool>(m, f);
          for (auto it = bool_field.begin();
              it != bool_field.end();
              ++it) {
            snprintf(buffer, sizeof(buffer), "%s%s", comma, *it ? "true" : "false");
            j->append(buffer);
            comma = ",";
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
        {
          //auto &string_field = r->GetRepeatedPtrField<std::string>(m, f);
          auto string_field = r->GetRepeatedFieldRef<std::string>(m, f);
          for (auto it = string_field.begin();
              it != string_field.end();
              ++it) {
            j->append(comma);
            comma = ",";
            if (f->type() == google::protobuf::FieldDescriptor::TYPE_STRING) {
              if (!append_string(*it, j)) {
                return false;
              }
            } else {
              if (!append_bytes(*it, j)) {
                return false;
              }
            }
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
        {
          //auto &message_field = r->GetRepeatedPtrField<google::protobuf::Message>(m, f);
          auto message_field = r->GetRepeatedFieldRef<google::protobuf::Message>(m, f);
          for (auto it = message_field.begin();
              it != message_field.end();
              ++it) {
            auto &o = *it;
            j->append(comma);
            comma = ",";
            if (!protobuf_to_json_proc(o, j)) {
              return false;
            }
          }
        }
        break;

       default:
        // can not be run here
        break;
      }

      j->append("]");
    } else {
      switch (f->cpp_type()) {
       case google::protobuf::FieldDescriptor::CPPTYPE_ENUM:
        snprintf(buffer, sizeof(buffer), "%d", r->GetEnum(m, f)->number());
        j->append(buffer);
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT:
        snprintf(buffer, sizeof(buffer), "%f", r->GetFloat(m, f));
        j->append(buffer);
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE:
        snprintf(buffer, sizeof(buffer), "%lf", r->GetDouble(m, f));
        j->append(buffer);
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_INT32:
        snprintf(buffer, sizeof(buffer), "%d", r->GetInt32(m, f));
        j->append(buffer);
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_INT64:
        snprintf(buffer, sizeof(buffer),
            "%lld", static_cast<long long>(r->GetInt64(m, f)));
        j->append(buffer);
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_UINT32:
        snprintf(buffer, sizeof(buffer), "%u", r->GetUInt32(m, f));
        j->append(buffer);
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_UINT64:
        snprintf(buffer, sizeof(buffer), "%llu",
            static_cast<unsigned long long>(r->GetUInt64(m, f)));

        j->append(buffer);
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_BOOL:
        j->append(r->GetBool(m, f) ? "true" : "false");
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_STRING:
        if (f->type() == google::protobuf::FieldDescriptor::TYPE_STRING) {
          if (!append_string(r->GetString(m, f), j)) {
            return false;
          }
        } else {
          if (!append_bytes(r->GetString(m, f), j)) {
            return false;
          }
        }
        break;

       case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
        if (!protobuf_to_json_proc(r->GetMessage(m, f, nullptr), j)) {
          return false;
        }
        break;
      };
    }
  }

  j->append("}");
  return true;
} // function protobuf_to_json_proc
#endif

bool json_to_protobuf(const std::string &j, google::protobuf::Message *m) {
  absl::string_view sv(j);
  auto status = google::protobuf::json::JsonStringToMessage(sv, m);
  if (!status.ok()) {
    return false;
  }
  return true;
}

bool protobuf_to_json(const google::protobuf::Message &m,
                      std::string *j,
                      bool for_response) {
  google::protobuf::util::JsonPrintOptions options;
  if (for_response) {
    //options.add_whitespace = true;                 // 格式化输出，带缩进
    options.always_print_fields_with_no_presence = true;  // 默认值是否输出
    options.always_print_enums_as_ints = true;  // 枚举转是否数字
    options.preserve_proto_field_names = true;  // 是否不改用小驼峰命名
    //options.unquote_int64_if_possible = true;

    //auto status = MessageToJsonString(m, j, options);
    return google::protobuf::json::MessageToJsonString(m, j, options).ok();
  }  else {
    options.preserve_proto_field_names = true;
    return google::protobuf::json::MessageToJsonString(m, j, options).ok();
  }
}

}  // namespace miku
