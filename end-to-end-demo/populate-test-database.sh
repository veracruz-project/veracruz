hash_value=$(dd skip=960 count=32 if=../sgx-root-enclave/css.bin bs=1 status=none| xxd -ps -cols 32)
echo $hash_value
rm -f proxy-attestation-server.db
echo "CREATE TABLE IF NOT EXISTS firmware_versions (id INTEGER, protocol TEXT, version_num TEXT, hash TEXT);" >> tmp.sql
echo "INSERT INTO firmware_versions VALUES(1, 'sgx', '0.3.0', '${hash_value}');" >> tmp.sql
sqlite3 proxy-attestation-server.db < tmp.sql
rm tmp.sql
