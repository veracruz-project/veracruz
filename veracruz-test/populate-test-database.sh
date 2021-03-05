hash_value=$(dd skip=960 count=32 if=../trustzone-root-enclave/css.bin bs=1 status=none| xxd -ps -cols 32)
echo $hash_value
rm -f proxy-attestation-server.db
diesel --config-file ../proxy-attestation-server/diesel.toml setup
echo "INSERT INTO firmware_versions VALUES(1, 'sgx', '0.3.0', '${hash_value}');" > tmp.sql
echo "INSERT INTO firmware_versions VALUES(2, 'psa', '0.3.0', 'deadbeefdeadbeefdeadbeefdeadbeeff00dcafef00dcafef00dcafef00dcafe');" >> tmp.sql
sqlite3 proxy-attestation-server.db < tmp.sql
