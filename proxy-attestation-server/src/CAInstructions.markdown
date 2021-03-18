```sh
openssl genrsa -out <KEY FILE> 4096
```
```sh
openssl req -x509 -new -nodes -key <KEY FILE> -sha256 -days 1825 -out <CERT FILE>
```