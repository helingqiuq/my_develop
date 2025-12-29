#include "efile/efile_mapping.h"
#include "util/util.h"
#include <iostream>

#include <string.h>

#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc < 4) {
    std::cerr << "args : <src_dir> <des_dir> <password>" << std::endl;
    return 1;
  }

  const char *src_path = argv[1];
  const char *des_path = argv[2];
  const char *password = argv[3];

  if (miku::create_unix_server(des_path)) {
    int32_t fd[2] = {0};
    int32_t ret = socketpair(AF_LOCAL, SOCK_STREAM, 0, fd);
    if (ret != 0) {
      std::cerr << "socketpair failed." << std::endl;
      return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
      std::cerr << "fork failed." << std::endl;
      return 1;
    }

    if (pid == 0) {  // child
      close(fd[0]);
      daemon(1, 1);

      miku::EfileFuseMapping em(src_path, des_path, password, true, false);

      em.Start(
          {},
          {
            [&](void *) -> void {
              miku::safe_write(fd[1], "1", 1);
              close(fd[1]);
            },
            nullptr
          },
          nullptr
          );
      exit(0);
    } else {
      // parent
      close(fd[1]);
      char buf[1] = {0};
      auto [r, n] = miku::safe_read(fd[0], buf, 1);
      if (!r || n != 1 || buf[0] != '1') {
        std::cerr << "read data from child failed." << std::endl;
        return -1;
      }
      close(fd[0]);
    }
  }

  return 0;
}
