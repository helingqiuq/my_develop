#pragma once

#include "middle/app_help.h"

class UserApp final : public miku::Application {
 public:
  using miku::Application::Application;
  virtual bool Initialize() override;
};
