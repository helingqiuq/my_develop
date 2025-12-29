#!/bin/bash

#创建
#req="{\"user_id\":1000,\"src_id\":0,\"user_type\":0,\"operator_id\":1000"
#req="${req},\"attrs\":[{\"k\":\"phonenum\",\"v\":\"13434703434\"}]}"
req="{\"user_id\":0,\"src_id\":0,\"user_type\":0,\"operator_id\":1000,\"gen_user_id\":true"
req="${req},\"attrs\":[{\"k\":\"phonenum\",\"v\":\"13434703434\"}]}"
#curl -X POST -d "${req}" http://127.0.0.1:5201/miku.user.interface/create

#更新
req="{\"user_id\":1000014,\"operator_id\":1000"
req="${req},\"attrs\":[{\"k\":\"merchant\",\"v\":\"\", \"op\":0}]}"
curl -X POST -d "${req}" http://127.0.0.1:5201/miku.user.interface/update

#冻结
req="{\"user_id\":1000,\"operator_id\":1000}"
#curl -X POST -d "${req}" http://127.0.0.1:5201/miku.user.interface/freeze

#解冻结
req="{\"user_id\":1000,\"operator_id\":1000}"
#curl -X POST -d "${req}" http://127.0.0.1:5201/miku.user.interface/unfreeze

#销户
req="{\"user_id\":1000,\"operator_id\":1000}"
#curl -X POST -d "${req}" http://127.0.0.1:5201/miku.user.interface/cancel

#查找
req="{\"user_id\":1000}"
req="{\"user_id\":1000003}"
#curl -X POST -d "${req}" http://127.0.0.1:5201/miku.user.interface/find
