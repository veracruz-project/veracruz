# Network stack in Veracruz

This document describes the network stack and the communication between various Veracruz components.

## Network stack for Veracruz Client -- Veracruz Server -- Runtime Manager

Network stack with default ports:
```
Veracruz Client               Veracruz Server                        Runtime Manager

+------------+                                                +----------------------------+
| VC message |                                                |         VC message         |
+------------+                                                +----------------------------+
|  protobuf  |                                                |          protobuf          |
+------------+                                                +----------------------------+
|    TLS     |                                                |                            |
+------------+      +------------+                            |                            |
|   base64   |      |   base64   |                            |            TLS             |
+------------+      +------------+                            |                            |
| VC session |      | VC session |                            |                            |
+------------+      +------------+  +------------------+      +----------------------------+
|    HTTP    |      |    HTTP    |  |     bincode      |      |          bincode           |
+------------+      +------------+  +------------------+      +----------------------------+
|    TCP     |      | TCP (3011) |  |   TCP (Linux)    |      |     TCP (6000) (Linux)     |
+------------+      +------------+  |   Unix socket    |      | Unix socket (5005) (Nitro) |
                                    | (Icecap & Nitro) |      |  VirtIO console (IceCap)   |
                                    +------------------+      +----------------------------+
```

On this plane, Veracruz components send messages to each other to request services or transfer files. For example, Veracruz Client can provision files to Runtime Manager, Veracruz Serve can request enclave teardown, Runtime Manager can send the results of the computation back to Veracruz Client, etc.
Each end-to-end message, i.e. between Veracruz Client and Runtime Manager, is serialized by the sender using `protobuf`, prefixed by its length, then gets encrypted at the TLS layer, then split into 16KB TLS records, sent one by one to the receiver. The first message chunk hence contains the protocol buffer's total length.
A buffering mechanism is implemented on the receiver side. This, along with the length prefix, allows to efficiently deal with large messages, e.g. files.
Veracruz Server has the role of replaying requests between Veracruz Client and Runtime Manager. It exposes an HTTP server on the client side and routes the encrypted messages to the right Runtime Manager instance identified by its session id.



## Network stack for the Proxy Attestation Server (TODO)
* PAS runs HTTP server:
/VerifyPAT
/Start
/PSA/
/Nitro/
* client & server connect to it
* PAS layers: HTTP, base64, protobuf
...
* PAS: 127.0.0.1:3010
