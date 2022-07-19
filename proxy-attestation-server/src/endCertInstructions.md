## Generate End-Entity Certificate

### Create a root CA

Genearte root CA key:
```sh
openssl genrsa -out ca_key.pem 4096
```
CA certificate configuration file:
```sh
cat>ca_crt.conf<<EOF
[ req ]
x509_extensions = v3_ca
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
CN=Company Internal Root-CA
[ v3_ca ]
subjectKeyIdentifier=hash
basicConstraints=critical,CA:true,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
EOF
```
Generate root CA certificate:
```sh
openssl req -new -sha256 -x509 -set_serial 1 -days 1825 -config ca_crt.conf -key ca_key.pem -out ca_crt.pem
```

### Create an interemdiate CA

Genearte CSR key:
```sh
openssl genrsa -out csr_key.pem 4096
```
CSR configuration file:
```sh
cat>inter_csr.conf<<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
CN=Internal Sub-CA (1)
EOF
```
Generate a CSR:
```sh
openssl req -sha256 -new -config inter_csr.conf -key csr_key.pem -nodes -out inter_csr.pem
```
Intermediate certificate configuration:
```sh
cat>inter_crt.conf<<EOF
subjectKeyIdentifier=hash
basicConstraints = critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign
EOF
```
```sh
openssl x509 -sha256 -CA ca_crt.pem -CAkey ca_key.pem -CAserial ca.srl -CAcreateserial -days 3700 -req -in inter_csr.pem -extfile inter_crt.conf -out inter_crt.pem
```
Intermediate CA configuration:
```sh
cat>inter_ca.conf<<EOF
dir = .
[ ca ]
default_ca = CA_default
[ CA_default ]
serial = $dir/inter_ca.srl
database = $dir/inter_ca.db
new_certs_dir = $dir
policy = policy_match
x509_extensions = v3_ca
[ v3_ca ]
[ policy_match ]
commonName = supplied
EOF

touch inter_ca.db
echo 01 > inter_ca.srl
```

### Create and sign a normal end-entity certificate

Generate end-entity key:
```sh
openssl genrsa -out end_key.pem 4096

cat>csr.conf<<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no
[ req_distinguished_name ]
CN=sub.domain.dom
EOF
openssl req -sha256 -new -config csr.conf -key end_key.pem -nodes -out csr.pem

cat>end_crt.conf<<EOF
basicConstraints = critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment,dataEncipherment,keyAgreement
extendedKeyUsage=critical,serverAuth,clientAuth,emailProtection
subjectAltName=critical,DNS:sub.domain.dom
EOF
```

Generate end-entity certificate and sign it:
```sh
openssl ca -md sha256 -utf8 -noemailDN -notext -config inter_ca.conf -cert inter_crt.pem -keyfile csr_key.pem -enddate 20251201050000Z -extfile end_crt.conf -in csr.pem -out end_crt.pem
```
Certificate chain:
```sh
cat end_crt.pem inter_crt.pem > chained_crt.pem
```
