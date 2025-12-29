#pragma once

#include <iostream>
#include <string>
#include <functional>
#include <memory>
#include <type_traits>
#include <tuple>

namespace miku {

template<typename F, typename TUPLE, std::size_t... I>
static auto apply_impl(const F &f, const TUPLE &t, std::index_sequence<I...>) -> auto {
  return f(std::get<I>(t)...);
}

template<typename F, typename TUPLE>
static auto apply(const F &f, const TUPLE &t) -> auto {
  return apply_impl(f, t, std::make_index_sequence<std::tuple_size_v<TUPLE>>());
}

template <typename T>
struct TypeChoose {
  using DesType = typename std::conditional<
    std::is_pointer_v<typename std::remove_reference<T>::type>,
        typename std::remove_reference<T>::type,
        typename std::conditional<std::is_rvalue_reference_v<T>,
            typename std::remove_reference<T>::type,
            const T &>::type>::type;

  using ArgType = typename std::conditional<
    std::is_pointer_v<typename std::remove_reference<T>::type>,
        typename std::remove_reference<T>::type,
        const typename std::remove_reference<T>::type &>::type;
};

struct TaskHelpUndefType {};

template <typename PROC_BEG, typename PROC_END, typename ... USER_DATA>
class TaskHelp final {
 public:
  TaskHelp(PROC_BEG proc_beg,
           PROC_END proc_end,
           USER_DATA ... user_data)
      : user_data_(user_data...)
      , proc_beg_(proc_beg)
      , proc_end_(proc_end) {
    if constexpr (!std::is_same_v<decltype(proc_beg_), TaskHelpUndefType>) {
      if constexpr (std::is_pointer_v<decltype(proc_beg_)>) {
        apply(*proc_beg_, user_data_);
      } else {
        apply(proc_beg_, user_data_);
      }
    }

#if 0
    if constexpr (std::is_reference_v<decltype(proc_)>) {
      std::cout << "proc_ is reference" << std::endl;
    } else if constexpr (std::is_pointer_v<decltype(proc_)>) {
      std::cout << "proc_ is point" << std::endl;
    } else {
      std::cout << "proc_ is value" << std::endl;
    }
#endif
  }

  ~TaskHelp() {
    if constexpr (!std::is_same_v<decltype(proc_end_), TaskHelpUndefType>) {
      if constexpr (std::is_pointer_v<decltype(proc_end_)>) {
        apply(*proc_end_, user_data_);
      } else {
        apply(proc_end_, user_data_);
      }
    }
  }

 private:
  std::tuple<USER_DATA ...> user_data_;
  PROC_BEG proc_beg_;
  PROC_END proc_end_;
};

template <typename PROC, typename ... USER_DATA>
auto make_ending_task(PROC &&proc, USER_DATA && ... user_data) {
  return std::make_shared<
    TaskHelp<TaskHelpUndefType,
             typename TypeChoose<decltype(proc)>::DesType,
             typename TypeChoose<decltype(user_data)>::DesType ...>>(
      TaskHelpUndefType{},
      std::forward<PROC>(proc),
      std::forward<USER_DATA>(user_data) ...);
}

template <typename PROC, typename ... USER_DATA>
auto make_begin_task(PROC &&proc, USER_DATA && ... user_data) {
  return std::make_shared<
    TaskHelp<typename TypeChoose<decltype(proc)>::DesType,
             TaskHelpUndefType,
             typename TypeChoose<decltype(user_data)>::DesType ...>>(
      std::forward<PROC>(proc),
      TaskHelpUndefType{},
      std::forward<USER_DATA>(user_data) ...);
}

template <typename PROC_BEG, typename PROC_END, typename ... USER_DATA>
auto make_auto_task(PROC_BEG &&proc_beg, PROC_END &&proc_end, USER_DATA && ... user_data) {
  return std::make_shared<
    TaskHelp<typename TypeChoose<decltype(proc_beg)>::DesType,
             typename TypeChoose<decltype(proc_end)>::DesType,
             typename TypeChoose<decltype(user_data)>::DesType ...>>(
      std::forward<PROC_BEG>(proc_beg),
      std::forward<PROC_END>(proc_end),
      std::forward<USER_DATA>(user_data) ...);
}

}  // namespace miku

#if 0
// demo

template <typename PROC, typename ... USER_DATA>
auto auto_report_atta_base(
    const char *atta_id,
    const char *atta_token,
    PROC &&proc,
    USER_DATA && ... user_data) {
  static_assert(std::is_same_v<decltype(proc(user_data...)), std::string>);
  static auto report_proc = [](
      const char *atta_id,
      const char *atta_token,
      typename miku::TypeChoose<decltype(proc)>::ArgType proc,
      typename miku::TypeChoose<decltype(user_data)>::ArgType ... user_data) -> int {
    std::cout << "atta_id = " << atta_id << std::endl;
    std::cout << "atta_token = " << atta_token << std::endl;
    std::string report_string = proc(user_data ...);
    std::cout << "report_string = " << proc(user_data ...) << std::endl;
    return 0;
  };

  return miku::make_ending_task(
      report_proc,
      atta_id,
      atta_token,
      std::forward<PROC>(proc),
      std::forward<USER_DATA>(user_data) ...);
}

#define report_abcd(proc, req, rsp) auto_report_atta_base("abcd_id", "abcd_token", proc, req, rsp);
#endif

