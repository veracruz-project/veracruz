
# diesel really wants to run in a rust project, so
# cd into proxy-attestation-server for this
#
# this also fixes issues of running this script from a
# different directory
#
db=$(realpath ${1:-proxy-attestation-server.db})
cd $(dirname $0)/../proxy-attestation-server

rm -f $db

diesel --config-file ../proxy-attestation-server/diesel.toml --database-url $db setup
echo "INSERT INTO firmware_versions VALUES(2, 'psa', '0.3.0', 'deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe');" >> tmp.sql
sqlite3 $db < tmp.sql
rm tmp.sql

