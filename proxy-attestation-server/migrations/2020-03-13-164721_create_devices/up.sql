CREATE TABLE devices (
    id INTEGER NOT NULL PRIMARY KEY,
    device_id INTEGER NOT NULL,
    pubkey_hash TEXT NOT NULL,
    enclave_name TEXT NOT NULL
);
CREATE TABLE firmware_versions(
    id INTEGER NOT NULL PRIMARY KEY,
    protocol TEXT NOT NULL,
    version_num TEXT NOT NULL,
    hash TEXT NOT NULL
)