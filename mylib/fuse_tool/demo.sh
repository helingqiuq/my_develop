#/bin/bash
./bazel-bin/fuse_tool/fuse_tool \
    --des_path=kk \
    --file_mapping=test_data:hello::/usr/bin/cat#md5c4702bac803cd6f723e0ac798b166331 \
    --log_output \
    --log_file=a.log

