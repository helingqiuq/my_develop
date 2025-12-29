#!/bin/bash


expire=$((`date +%s` + 30000))
#创建
#req="{\"type\":1,\"activity_id\":\"test_activity_id\",\"activity_cycle\":\"test_activity_cycle\",\"coupon_no\":\"test_coupon_no\",\"coupon_conf\":{\"no_threshold_info\":{\"amount\":100}},\"expire\":${expire},\"operator_id\":666}"
req="{\"type\":1,\"activity_id\":\"lsf_product_test\",\"activity_cycle\":\"test_activity_cycle\",\"coupon_no\":\"abcde\",\"coupon_conf\":{\"no_threshold_info\":{\"amount\":500}},\"expire\":${expire},\"operator_id\":666}"
curl -X POST -d "${req}" http://127.0.0.1:5101/miku.coupon.interface/create

#启用
req="{\"user_id\":77889,\"operator_id\":99887,\"coupon_no\":\"test_coupon_no3\"}"
#curl -X POST -d "${req}" http://127.0.0.1:5101/miku.coupon.interface/invocation

#核销
req="{\"activity_id\":\"test_activity_id\",\"activity_cycle\":\"test_activity_cycle\",\"coupon_no\":\"test_coupon_no\",\"operator_id\":8888}"
#curl -X POST -d "${req}" http://127.0.0.1:5101/miku.coupon.interface/exchange

#作废
#req="{\"coupon_no\":\"test_coupon_no\",\"operator_id\":9999,\"force\":false}"
req="{\"coupon_no\":\"test_coupon_no\",\"operator_id\":9999,\"force\":true}"
#curl -X POST -d "${req}" http://127.0.0.1:5101/miku.coupon.interface/cancel

#过期
req="{\"coupon_no\":\"test_coupon_no\",\"operator_id\":8899}"
#curl -X POST -d "${req}" http://127.0.0.1:5101/miku.coupon.interface/expire
