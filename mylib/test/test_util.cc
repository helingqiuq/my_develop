#include "util/util.h"

#include <iostream>
#include <stdio.h>

int main(int argc, char *argv[]) {
  std::cout << *miku::get_module_script(atoi(argv[1])) << std::endl;
  std::cout << *miku::get_module_path(atoi(argv[1])) << std::endl;
  return 0;
}
