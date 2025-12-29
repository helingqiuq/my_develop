#pragma once

#include "middle/app_help.h"

class LoginApp final : public miku::Application {
 public:
  using miku::Application::Application;
  virtual bool Initialize() override;
};
