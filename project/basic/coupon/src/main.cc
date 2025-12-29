#include "coupon_app.h"
#include "coupon_service.h"
#include "request_map.h"
#include "util/log.h"
#include "util/util.h"

bool CouponApp::Initialize() {
  static CouponServiceConfig config;
  const auto &conf = Config();

  config.sign_key = miku::cfg_get_s(conf, "sign_key", "");
  if (config.sign_key.empty()) {
    LogError("unset sign_key.");
    return false;
  }

  config.schema_bname = miku::cfg_get_s(conf, "schema_base_name", "coupon");
  config.table_bname = miku::cfg_get_s(conf, "table_base_name", "coupon");
  config.record_bname = miku::cfg_get_s(conf, "record_base_name", "record");

  // grpc
  auto starget = miku::cfg_get_s(conf, "service.target", "0.0.0.0:50022");
  auto sname = miku::cfg_get_s(conf, "service.name", "coupon_service");

  static CouponServiceContext ctx(config);
  RegisterService({sname, starget}, new CouponServiceImpl(ctx));

  // db
  std::vector<miku::MysqlHandler::MysqlHandlerConf> dconfs;
  for (const auto &c : conf["dbconf"]) {
    const auto &dhost = miku::cfg_get_s(c, "host", "");
    const auto &dport = miku::cfg_get_ui(c, "port", 0);
    const auto &duser = miku::cfg_get_s(c, "user", "");
    const auto &dpasswd = miku::cfg_get_s(c, "passwd", "");
    const auto &dschema = miku::cfg_get_s(c, "schema", "");

    if (dhost.empty() || dport == 0 || dschema.empty()) {
      LogError("some config is empty." << "host = " << dhost
                                       << "port = " << dport
                                       << "schema = " << dschema);
      return false;
    }

    dconfs.push_back({dhost, dport, duser, dpasswd, dschema});
  }

  if (!ctx.mysql_router.Initailize(dconfs)) {
    LogError("mysql_router.Initialize failed.");
    return false;
  }

  for (uint32_t i = 0; i < CouponServiceContext::schema_count; i++) {
    auto [proxy, sidx, tidx] = ctx.mysql_router.GetProxy(
             i * CouponServiceContext::table_count);
    if (proxy->ExecuteQuery("select 1") != 0) {
      LogError("check connect: " << sidx << " " << tidx << " failed");
    } else {
      LogInfo("check connect: " << sidx << " " << tidx << " success");
    }
  }


  // http
  auto hshost = miku::cfg_get_s(conf, "http_service.host", "127.0.0.1");
  auto hsport = miku::cfg_get_ui(conf, "http_service.port", 5101);
  auto hsparallel = miku::cfg_get_ui(conf, "http_service.parallel", 1);
  auto hstimeout = miku::cfg_get_ui(conf, "http_service.timeout", 0);
  auto hscert_file = miku::cfg_get_s(conf, "http_service.cert_file", "");
  auto hskey_file = miku::cfg_get_s(conf, "http_service.key_file", "");

  RegisterHttpService(HTTP_HELP_GRPC_SERVICE_SV(miku::coupon, interface),
      {hshost, hsport, hsparallel, hstimeout, hscert_file, hskey_file});

  CLIENT_HELP_INITIALIZE(Coupon)({
      "", {miku::cfg_get_s(conf, "client.self.target", "127.0.0.1:50022")}});

  RequestMap(HTTP_HELP_GRPC_REGISTER_CB, Coupon, miku::coupon, interface);
  RegisterHttpDefaultCb(miku::http_service::http_request_handler_default, nullptr);

  return true;
}


int main(int argc, char **argv) {
  CouponApp app;
  app.Main(argc, argv);
  return 0;
}
