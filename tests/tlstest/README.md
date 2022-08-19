# Stand-alone test of TLS connection using mbedtls crate

This is partly a unit test, but mostly to provide an easy way of
experimenting with different client/server configurations, different
types of certificate and so on, because everything is in one fairly
short source file.

Before running the program, generate keys and certificates:

``` bash
openssl ecparam -name prime256v1 -genkey > server-key.pem
openssl req -x509 -days 365 -key server-key.pem -out server-crt.pem \
  -subj /CN=server

openssl ecparam -name prime256v1 -genkey > client-key.pem

openssl req -new -key client-key.pem -out client-csr.pem \
  -subj /CN=client

openssl x509 -req -CA server-crt.pem -CAkey server-key.pem \
  -in client-csr.pem -out client-crt.pem

cargo run
```

The server certificate (`server-crt.pem`) is also the CA certificate.

The client certificate (`client-crt.pem`) has to be signed with the
server certificate because the server is configured with
`AuthMode::Required`; otherwise the client certificate could be
self-signed.
