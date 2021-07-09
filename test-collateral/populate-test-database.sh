
# diesel really wants to run in a rust project, so
# cd into proxy-attestation-server for this
#
# this also fixes issues of running this script from a
# different directory
#
db=$(realpath ${1:-proxy-attestation-server.db})
cd $(dirname $0)/../proxy-attestation-server

rm -f $db

# SGX hash
if [ -f ../sgx-root-enclave/css.bin ]
then
	sgx_hash=$(dd skip=960 count=32 if=../sgx-root-enclave/css.bin bs=1 status=none| xxd -ps -cols 32)
	echo $sgx_hash
fi

# Nitro hash
if [ -f ../nitro-root-enclave/PCR0 ]
then
	nitro_hash=$(cat ../nitro-root-enclave/PCR0)
fi

diesel --config-file ../proxy-attestation-server/diesel.toml --database-url $db setup
echo "INSERT INTO firmware_versions VALUES(1, 'sgx', '0.3.0', '${sgx_hash:-}');" > tmp.sql
echo "INSERT INTO firmware_versions VALUES(2, 'psa', '0.3.0', 'deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe');" >> tmp.sql
echo "INSERT INTO firmware_versions VALUES(3, 'nitro', '0.1.0', '${nitro_hash:-}');" >> tmp.sql
sqlite3 $db < tmp.sql
rm tmp.sql

