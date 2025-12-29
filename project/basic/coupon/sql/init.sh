#! /bin/sh

if [ $# -ne 5 ]; then
    echo "${0} <host> <port> <user> <pass> <schema_id>"
    exit 1
fi

HOST="${1}"
PORT="${2}"
USER="${3}"
PASS="${4}"
ID="${5}"
TEMP='temp.sql'

RUSER="'coupon_readonly'@'%'"
WUSER="'coupon_write'@'%'"
SUSER="'coupon_super'@'%'"
AUSER="'coupon_root'@'%'"

rm -f "${TEMP}"
echo "
DROP USER IF EXISTS ${RUSER};
CREATE USER ${RUSER} IDENTIFIED WITH caching_sha2_password BY 'coupon_readonly';
DROP USER IF EXISTS ${WUSER};
CREATE USER ${WUSER} IDENTIFIED WITH caching_sha2_password BY 'coupon_write';
DROP USER IF EXISTS ${SUSER};
CREATE USER ${SUSER} IDENTIFIED WITH caching_sha2_password BY 'coupon_super';
DROP USER IF EXISTS ${AUSER};
CREATE USER ${AUSER} IDENTIFIED WITH caching_sha2_password BY 'coupon_root';
GRANT SELECT,INSERT,UPDATE,DELETE ON \`coupon\\_%\`.* TO ${SUSER};
GRANT ALL ON \`coupon\\_%\`.* TO ${AUSER} WITH GRANT OPTION;
GRANT SELECT,INSERT,UPDATE ON \`coupon\\_%\`.* TO ${WUSER};
GRANT SELECT ON \`coupon\\_%\`.* TO ${RUSER};
DROP SCHEMA IF EXISTS \`coupon_${ID}\`;
CREATE SCHEMA \`coupon_${ID}\`;
USE \`coupon_${ID}\`;
SOURCE empty.sql;" >"${TEMP}" || exit 1

for i in `seq 0 99`; do
echo "CREATE TABLE \`coupon_${i}\` LIKE \`template_coupon\`;
GRANT UPDATE(\`user_id\`,\`attr\`,\`status\`,\`updated\`,\`started\`,\`expired\`,\`redemption\`,\`cancel\`,\`extension\`,\`context\`,\`extension\`,\`signature\`) ON \`coupon_${i}\` TO ${WUSER};
CREATE TABLE \`record_${i}_2025\` LIKE \`template_record\`;
CREATE TABLE \`record_${i}_2026\` LIKE \`template_record\`;
CREATE TABLE \`record_${i}_2027\` LIKE \`template_record\`;
CREATE TABLE \`record_${i}_2028\` LIKE \`template_record\`;
CREATE TABLE \`record_${i}_2029\` LIKE \`template_record\`;
CREATE TABLE \`record_${i}_2030\` LIKE \`template_record\`;" >>"${TEMP}" || exit 1
done

mysql -h "${HOST}" -P "${PORT}" -u"${USER}" -p"${PASS}" <"${TEMP}" || exit 1
rm -f "${TEMP}"
exit $?
