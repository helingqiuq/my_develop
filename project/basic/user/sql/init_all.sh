#! /bin/sh

schema_cnt=8
if [ $# -ne 4 ]; then
    echo "${0} <host> <port> <user> <pass>"
    exit 1
fi

for i in `seq 0 $((${schema_cnt} - 1))`; do
  ./init.sh ${1} ${2} ${3} ${4} ${i}
done
