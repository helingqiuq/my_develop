#include "efile/efile.h"
#include "util/util.h"

#include <iostream>

int main(int argc, char *argv[]) {
  if (argc == 1) {
    miku::EFile f("eeeeeeeeeefile", "1234", true);
    std::string s = miku::make_random_string(40000);
    f.write(s.c_str(), 40000);
    std::cout << s << std::endl;
    f.close();
  } else {
    miku::EFile f("eeeeeeeeeefile", "1234");
    char buf[4097] = {0};
    f.seek(0, SEEK_SET);
    auto r = f.read(buf, 4096);
    std::cout << buf << std::endl;
    std::cout << "r = " << r << std::endl;
    std::cout << "last_errno = " << f.last_errno() << std::endl;
    std::cout << "last_err_info = " << f.last_err_info() << std::endl;
    f.close();
  }
  return 0;
}
