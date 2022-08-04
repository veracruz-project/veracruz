```sh
openssl ecparam -name prime256v1 -genkey -out <KEY FILE>
```
Generate ECDSA Prime456r1 key:
```sh
openssl ecparam -name prime256v1 -genkey -out <PRIVATE KEY FILE>
```
```sh
openssl req -x509 -key <KEY FILE> -sha256 -days 1825 -out <CERT FILE>
```
Generate a CSR:
```sh
openssl req -key <KEY FILE> -sha256 -out <CSR FILE> -keyform pem -outform der
```
