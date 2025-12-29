#!/bin/bash

#注册
#req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\",\"type\":1, \"user_id\":1000}"
req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\",\"type\":0, \"user_id\":1000, \"attrs\":[{\"k\":\"auth_secret\",\"v\":\"1234\"}]}"
req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\",\"type\":1, \"user_id\":1000,\"params\":[{\"k\":\"fight_date\",\"v\":\"20251212\"}]}"
#curl -X POST -d "${req}" http://127.0.0.1:5211/miku.login.interface/register

#登陆
#req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\", \"attrs\":[{\"k\":\"auth_secret\",\"v\":\"1234\"}]}"
#req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\"}"
#req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\", \"attrs\":[{\"k\":\"auth_secret\",\"v\":\"12345\"}]}"
req="{\"appid\":\"lsf_product\",\"auth_key\":\"test_merchant_id\", \"attrs\":[{\"k\":\"auth_secret\",\"v\":\"test_merchant_id\"}]}"
curl -X POST -d "${req}" http://127.0.0.1:5211/miku.login.interface/login

#更新
req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\",\"attrs\":[{\"k\":\"auth_secret\",\"v\":\"12345\"}]}"
#curl -X POST -d "${req}" http://127.0.0.1:5211/miku.login.interface/update

#冻结
req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\"}"
#curl -X POST -d "${req}" http://127.0.0.1:5211/miku.login.interface/freeze

#解冻结
req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\"}"
#curl -X POST -d "${req}" http://127.0.0.1:5211/miku.login.interface/unfreeze

#销户
req="{\"appid\":\"test_appid\",\"auth_key\":\"6666\"}"
#curl -X POST -d "${req}" http://127.0.0.1:5211/miku.login.interface/cancel

#查找
req="{\"appid\":\"lsf_product\",\"auth_key\":\"test_merchant_id\"}"
#curl -X POST -d "${req}" http://127.0.0.1:5211/miku.login.interface/find
