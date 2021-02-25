hash_value=$(dd skip=960 count=32 if=../sonora/css.bin bs=1 status=none| xxd -ps -cols 32)
echo $hash_value
rm -f proxy-attestation-server.db
diesel setup
echo "INSERT INTO firmware_versions VALUES(1, 'sgx', '0.0.1', '${hash_value}')" > tmp.sql
sqlite3 proxy-attestation-server.db < tmp.sql
