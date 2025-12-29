#pragma once
namespace miku {
template <typename T>
class Singleton {
 private:
  Singleton() = default;
  virtual ~Singleton() = default;
  Singleton(const Singleton&) = delete;
  Singleton& operator=(const Singleton&) = delete;

 public:
  static T *Get() {
    static T instance;
    return &instance;
  }
};
}
