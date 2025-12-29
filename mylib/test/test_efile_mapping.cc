#include "efile/efile_mapping.h"
#include "util/util.h"
#include <iostream>
#include <memory>
#include <string.h>

#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc < 3) {
    std::cerr << "args : <src_dir> <des_dir>" << std::endl;
    return 1;
  }

  miku::EfileFuseMapping em(argv[1], argv[2], "1234", true, true);
  //em.Start({"-d"});
  //em.AddAuthInfo("/", "/usr/bin/cat#md5c4702bac803cd6f723e0ac798b166331");
  em.AddAuthInfo("/", "/root/.cache/bazel/_bazel_root/e6ad5a1b292039d5cb693cb3ec8fd661/execroot/__main__/bazel-out/k8-fastbuild/bin/test/test_efile_mapping");
  em.AddAuthInfo("/1", "/usr/bin/cat#md5c4702bac803cd6f723e0ac798b166331#scriptfuse_des/1#script_md5125585b1e0af8330b2e271230b053a4e");
  //em.AddAuthInfo("/1", "/usr/bin/cat#md5c4702bac803cd6f723e0ac798b166331#scriptfuse_des/1");
  em.Start();
  return 0;
}
