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

RUSER="'user_readonly'@'%'"
WUSER="'user_write'@'%'"
SUSER="'user_super'@'%'"
AUSER="'user_root'@'%'"

rm -f "${TEMP}"
echo "
DROP USER IF EXISTS ${RUSER};
CREATE USER ${RUSER} IDENTIFIED WITH caching_sha2_password BY 'user_readonly';
DROP USER IF EXISTS ${WUSER};
CREATE USER ${WUSER} IDENTIFIED WITH caching_sha2_password BY 'user_write';
DROP USER IF EXISTS ${SUSER};
CREATE USER ${SUSER} IDENTIFIED WITH caching_sha2_password BY 'user_super';
DROP USER IF EXISTS ${AUSER};
CREATE USER ${AUSER} IDENTIFIED WITH caching_sha2_password BY 'user_root';
GRANT SELECT,INSERT,UPDATE,DELETE ON \`user\\_%\`.* TO ${SUSER};
GRANT ALL ON \`user\\_%\`.* TO ${AUSER} WITH GRANT OPTION;
GRANT SELECT,INSERT,UPDATE ON \`user\\_%\`.* TO ${WUSER};
GRANT SELECT ON \`user\\_%\`.* TO ${RUSER};
DROP SCHEMA IF EXISTS \`user_${ID}\`;
CREATE SCHEMA \`user_${ID}\`;
USE \`user_${ID}\`;
SOURCE empty.sql;" >"${TEMP}" || exit 1

for i in `seq 0 99`; do
echo "CREATE TABLE \`user_${i}\` LIKE \`template_user\`;
GRANT UPDATE(\`status\`,\`type\`,\`param\`,\`attr\`,\`updated\`,\`context\`,\`extension\`,\`signature\`) ON \`user_${i}\` TO ${WUSER};
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
