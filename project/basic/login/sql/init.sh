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

RUSER="'login_readonly'@'%'"
WUSER="'login_write'@'%'"
SUSER="'login_super'@'%'"
AUSER="'login_root'@'%'"

rm -f "${TEMP}"
echo "
DROP USER IF EXISTS ${RUSER};
CREATE USER ${RUSER} IDENTIFIED WITH caching_sha2_password BY 'login_readonly';
DROP USER IF EXISTS ${WUSER};
CREATE USER ${WUSER} IDENTIFIED WITH caching_sha2_password BY 'login_write';
DROP USER IF EXISTS ${SUSER};
CREATE USER ${SUSER} IDENTIFIED WITH caching_sha2_password BY 'login_super';
DROP USER IF EXISTS ${AUSER};
CREATE USER ${AUSER} IDENTIFIED WITH caching_sha2_password BY 'login_root';
GRANT SELECT,INSERT,UPDATE,DELETE ON \`login\\_%\`.* TO ${SUSER};
GRANT ALL ON \`login\\_%\`.* TO ${AUSER} WITH GRANT OPTION;
GRANT SELECT,INSERT,UPDATE ON \`login\\_%\`.* TO ${WUSER};
GRANT SELECT ON \`login\\_%\`.* TO ${RUSER};
DROP SCHEMA IF EXISTS \`login_${ID}\`;
CREATE SCHEMA \`login_${ID}\`;
USE \`login_${ID}\`;
SOURCE empty.sql;" >"${TEMP}" || exit 1

for i in `seq 0 99`; do
echo "CREATE TABLE \`login_${i}\` LIKE \`template_login\`;
GRANT UPDATE(\`status\`,\`attr\`,\`user_id\`,\`updated\`,\`context\`,\`extension\`,\`signature\`) ON \`login_${i}\` TO ${WUSER};" >>"${TEMP}" || exit 1
done

mysql -h "${HOST}" -P "${PORT}" -u"${USER}" -p"${PASS}" <"${TEMP}" || exit 1
rm -f "${TEMP}"
exit $?
