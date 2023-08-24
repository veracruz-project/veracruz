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
                                    |     (Nitro)      |      |                            |
                                    +------------------+      +----------------------------+
```

On this plane, Veracruz components send messages to each other to request services or transfer files. For example, Veracruz Client can provision files to Runtime Manager, Veracruz Serve can request enclave teardown, Runtime Manager can send the results of the computation back to Veracruz Client, etc.
Each end-to-end message, i.e. between Veracruz Client and Runtime Manager, is serialized by the sender using `protobuf`, prefixed by its length, then gets encrypted at the TLS layer, then split into 16KB TLS records, sent one by one to the receiver. The first message chunk hence contains the protocol buffer's total length.
A buffering mechanism is implemented on the receiver side. This, along with the length prefix, allows to efficiently deal with large messages, e.g. files.
Veracruz Server has the role of replaying requests between Veracruz Client and Runtime Manager. It exposes an HTTP server on the client side and routes the encrypted messages to the right Runtime Manager instance identified by its session id.



## Proxy Attestation Server

### Services
The Proxy Attestation Server provides several services over HTTP:
* `/VerifyPAT`: Verify proxy attestation token by looking for a device ID match in the database. Requested by Veracruz Client
* `/Start`: Start attestation and return a device ID and a challenge. Requested by Veracruz Server
* `/PSA`: Receive native (PSA) attestation token from Veracruz Server
* `/Nitro`: Receive Nitro attestation token from Veracruz Server

### Network stack
```
+---------------------+
| Attestation message |
+---------------------+
|      protobuf       |
+---------------------+
|       base64        |
+---------------------+
|        HTTP         |
+---------------------+
|         TCP         |
+---------------------+
```
