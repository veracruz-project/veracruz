/*
 * mini-durango - A Veracruz client targetting microcontroller devices
 *
 */

#include <stdio.h>
#include <stdlib.h>

//#if !defined(__ZEPHYR__) || defined(CONFIG_POSIX_API)
//
//#include <netinet/in.h>
//#include <sys/socket.h>
//#include <arpa/inet.h>
//#include <unistd.h>
//#include <netdb.h>
//
//#else

#include <net/socket.h>
#include <net/http_client.h>
#include <random/rand32.h>
#include <kernel.h>

#include "nanopb/pb.h"
#include "nanopb/pb_encode.h"
#include "nanopb/pb_decode.h"
#include "transport_protocol.pb.h"

// TODO log?
//#include <logging/log.h>
//LOG_MODULE_REGISTER(http, CONFIG_FOO_LOG_LEVEL);

//#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
//#include <net/tls_credentials.h>
//#include "ca_certificate.h"
//#endif
//
//#endif

///* HTTP server to connect to */
////#define HTTP_HOST "google.com"
////#define HTTP_HOST "172.217.1.228"
//#define HTTP_HOST "172.17.0.2"
///* Port to connect to, as string */
//#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
//#define VERACRUZ_SERVER_PORT "443"
//#else
////#define VERACRUZ_SERVER_PORT "80"
//#define VERACRUZ_SERVER_PORT "3017"
//#endif
///* HTTP path to request */
//#define HTTP_PATH "/"
//
//
//#define SSTRLEN(s) (sizeof(s) - 1)
//#define CHECK(r) { if (r == -1) { printf("Error: " #r "\n"); exit(1); } }
//
//#define REQUEST "GET " HTTP_PATH " HTTP/1.0\r\nHost: " HTTP_HOST "\r\n\r\n"
//
//static char response[1024];
//
//void dump_addrinfo(const struct addrinfo *ai)
//{
//	printf("addrinfo @%p: ai_family=%d, ai_socktype=%d, ai_protocol=%d, "
//	       "sa_family=%d, sin_port=%x\n",
//	       ai, ai->ai_family, ai->ai_socktype, ai->ai_protocol,
//	       ai->ai_addr->sa_family,
//	       ((struct sockaddr_in *)ai->ai_addr)->sin_port);
//}

//// HTTP stuff ////

// TODO use generated policy.h
#ifndef VERACRUZ_SERVER_HOST
#define VERACRUZ_SERVER_HOST "172.17.0.2"
#endif

#ifndef VERACRUZ_SERVER_PORT
#define VERACRUZ_SERVER_PORT 3017
#endif

// TODO common prefix for veracruz client functions?
#ifndef VERACRUZ_TIMEOUT
#define VERACRUZ_TIMEOUT 3000
#endif

#ifndef PROXY_ATTESTATION_SERVER_HOST
#define PROXY_ATTESTATION_SERVER_HOST "172.17.0.2"
#endif

#ifndef PROXY_ATTESTATION_SERVER_PORT
#define PROXY_ATTESTATION_SERVER_PORT 3010
#endif

struct http_get_state {
    uint8_t *buf;
    size_t buf_len;
    size_t pos;
};

static void http_get_cb(
        struct http_response *rsp,
        enum http_final_call final,
        void *udata) {
//    // TODO probably handle this?
//    if (state != HTTP_DATA_MORE) {
//        printf("http rsp state != HTTP_DATA_FINAL (%d), "
//            "should handle this\n", state);
//    }

    printf("rsp = %s (%d bytes)\n", rsp->http_status, rsp->data_len);

    struct http_get_state *state = udata;
    uint8_t *start = (rsp->body_start) ? rsp->body_start : rsp->recv_buf;
    size_t len = rsp->processed - state->pos;

    if (state->pos + len > state->buf_len) {
        printf("http get buffer overflow! truncating (%d > %d)\n",
            state->pos + len, state->buf_len);

        len = state->buf_len - state->pos;
    }

    memcpy(&state->buf[state->pos], start, len);
    state->pos += len;
}

// TODO TLS? https_get?
ssize_t http_get(
        const char *host,
        uint16_t port,
        const char *path,
        // TODO headers?
        uint8_t *buf,
        size_t buf_len) {
    // setup address, TODO use DNS?
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    // allocate packet buffer for managing http connection
    void *pbuf = malloc(256);
    size_t pbuf_len = 256;
    if (!pbuf) {
        printf("http malloc failed (-ENOMEM)\n");
        return -ENOMEM;
    }

    // create socket and connect to server
    // TODO IPv6? can use net_sin(addr)->sin_family here
    // DNS? Take in a string more useful API?
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        printf("http socket open failed (%d)\n", -errno);
        free(pbuf);
        return -errno;
    }

    int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0) {
        printf("http connect failed (%d)\n", -errno);
        free(pbuf);
        close(sock);
        return -errno;
    }

    // state for filling in buffer
    struct http_get_state state = {
        .buf = buf,
        .buf_len = buf_len,
        .pos = 0,
    };

    // perform client request, Zephyr handles most of this for us
    struct http_request req = {
        .method = HTTP_GET,
        .url = path,
        .host = host,
        .protocol = "HTTP/1.1",
        .response = http_get_cb,
        .recv_buf = pbuf,
        .recv_buf_len = pbuf_len,
    };

    int err = http_client_req(sock, &req, VERACRUZ_TIMEOUT, &state);
    if (err < 0) {
        printf("http req failed (%d)\n", err);
        free(pbuf);
        close(sock);
        return err;
    }

    // done, close
    free(pbuf);
    close(sock);
    return state.pos;
}

ssize_t http_post(
        const char *host,
        uint16_t port,
        const char *path,
        // TODO headers?
        const uint8_t *payload_buf,
        size_t payload_buf_len,
        uint8_t *resp_buf,
        size_t resp_buf_len) {
    // setup address, TODO use DNS?
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    // allocate packet buffer for managing http connection
    void *pbuf = malloc(256);
    size_t pbuf_len = 256;
    if (!pbuf) {
        printf("http malloc failed (-ENOMEM)\n");
        return -ENOMEM;
    }

    // create socket and connect to server
    // TODO IPv6? can use net_sin(addr)->sin_family here
    // DNS? Take in a string more useful API?
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        printf("http socket open failed (%d)\n", -errno);
        free(pbuf);
        return -errno;
    }

    int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0) {
        printf("http connect failed (%d)\n", -errno);
        free(pbuf);
        close(sock);
        return -errno;
    }

    // state for filling in buffer
    struct http_get_state state = {
        .buf = resp_buf,
        .buf_len = resp_buf_len,
        .pos = 0,
    };

    // perform client request, Zephyr handles most of this for us
    struct http_request req = {
        .method = HTTP_POST,
        .url = path,
        .host = host,
        .protocol = "HTTP/1.1",
        .response = http_get_cb,
        .payload = payload_buf,
        .payload_len = payload_buf_len,
        .recv_buf = pbuf,
        .recv_buf_len = pbuf_len,
    };

    int err = http_client_req(sock, &req, VERACRUZ_TIMEOUT, &state);
    if (err < 0) {
        printf("http req failed (%d)\n", err);
        free(pbuf);
        close(sock);
        return err;
    }

    // done, close
    free(pbuf);
    close(sock);
    return state.pos;
}

//// base64 ////

size_t base64_encode_size(size_t in_len) {
    size_t x = in_len;
    if (in_len % 3 != 0) {
        x += 3 - (in_len % 3);
    }

    return 4*(x/3);
}

static const char BASE64_ENCODE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
ssize_t base64_encode(
        const uint8_t *in, size_t in_len,
        char *out, size_t out_len) {
    size_t e_len = base64_encode_size(in_len);
    if (e_len+1 > out_len) {
        return -EOVERFLOW;
    }
    out[e_len] = '\0';

    for (size_t i=0, j=0; i < in_len; i += 3, j += 4) {
        size_t v = in[i];
        v = i+1 < e_len ? (v << 8 | in[i+1]) : (v << 8);
        v = i+2 < e_len ? (v << 8 | in[i+2]) : (v << 8);

        out[j]   = BASE64_ENCODE[(v >> 18) & 0x3f];
        out[j+1] = BASE64_ENCODE[(v >> 12) & 0x3f];

        if (i+1 < in_len) {
            out[j+2] = BASE64_ENCODE[(v >> 6) & 0x3f];
        } else {
            out[j+2] = '=';
        }

        if (i+2 < in_len) {
            out[j+3] = BASE64_ENCODE[v & 0x3f];
        } else {
            out[j+3] = '=';
        }
    }

    return e_len;
}

size_t base64_decode_size(const char *in) {
    size_t in_len = strlen(in);

    size_t x = 3*(in_len/4);
    for (size_t i = 0; i < in_len && in[in_len-i-1] == '='; i++) {
        x -= 1;
    }

    return x;
}

static const int8_t BASE64_DECODE[] = {
    62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1,
    -1, -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

static bool base64_isvalid(char c) {
    if (c >= '0' && c <= '9') {
        return true;
    } else if (c >= 'A' && c <= 'Z') {
        return true;
    } else if (c >= 'a' && c <= 'z') {
        return true;
    } else if (c == '+' || c == '/' || c == '=') {
        return true;
    } else {
        return false;
    }
}

ssize_t base64_decode(
        const char *in,
        char *out, size_t out_len) {
    size_t in_len = strlen(in);
    if (in_len % 4 != 0) {
        return -EINVAL;
    }

    size_t d_len = base64_decode_size(in);
    if (d_len > out_len) {
        return -EOVERFLOW;
    }

    for (size_t i = 0; i < in_len; i++) {
        if (!base64_isvalid(in[i])) {
            return -EILSEQ;
        }
    }

    for (size_t i=0, j=0; i < in_len; i += 4, j += 3) {
        size_t v = BASE64_DECODE[in[i]-43];
        v = (v << 6) | BASE64_DECODE[in[i+1]-43];
        v = in[i+2] == '=' ? (v << 6) : ((v << 6) | BASE64_DECODE[in[i+2]-43]);
        v = in[i+3] == '=' ? (v << 6) : ((v << 6) | BASE64_DECODE[in[i+3]-43]);

        out[j] = (v >> 16) & 0xff;

        if (in[i+2] != '=') {
            out[j+1] = (v >> 8) & 0xff;
        }

        if (in[i+3] != '=') {
            out[j+2] = v & 0xff;
        }
    }

    return d_len;
}




//// application logic ////

uint8_t buffer[10*1024];
uint8_t buffer2[10*1024];

// hack to exit QEMU
//__attribute__((noreturn))
void qemu_exit(void) {
    __asm__ volatile (
        "mov r0, #0x18 \n\t"
        "ldr r1, =#0x20026 \n\t"
        "bkpt #0xab \n\t"
    );
}

void xxd(const void *pbuf, size_t len) {
    const uint8_t *buf = pbuf;

    for (int i = 0; i < len; i += 16) {
        printf("%08x: ", i);

        for (int j = 0; j < 16; j++) {
            if (i+j < len) {
                printf("%02x ", buf[i+j]);
            } else {
                printf("   ");
            }
        }

        printf(" ");

        for (int j = 0; j < 16 && i+j < len; j++) {
            if (i+j < len) {
                if (buf[i+j] >= ' ' && buf[i+j] <= '~') {
                    printf("%c", buf[i+j]);
                } else {
                    printf(".");
                }
            } else {
                printf(" ");
            }
        }

        printf("\n");
    }
}

void main(void)
{
    // get random challenge
    // TODO Zephyr notes this is not cryptographically secure, is that an
    // issue? This will be an area to explore
    uint8_t challenge[32];
    sys_rand_get(challenge, sizeof(challenge));

    // TODO log? can we incrementally log?
    printf("attest: challenge: ");
    for (int i = 0; i < sizeof(challenge); i++) {
        printf("%02x", challenge[i]);
    }
    printf("\n");

    // construct attestation token request
    Tp_RuntimeManagerRequest request = {
        .which_message_oneof = Tp_RuntimeManagerRequest_request_proxy_psa_attestation_token_tag
    };
    memcpy(request.message_oneof.request_proxy_psa_attestation_token.challenge,
            challenge, sizeof(challenge));

    // encode
    // TODO this could be smaller, but instead could we tie protobuf encoding
    // directly into our GET function?
    uint8_t request_buf[256];
    pb_ostream_t request_stream = pb_ostream_from_buffer(
            request_buf, sizeof(request_buf));
    pb_encode(&request_stream, &Tp_RuntimeManagerRequest_msg, &request);

    // convert base64
    // TODO if base64 was reversed this could operate in-place
    char request_b64_buf[256];
    ssize_t request_b64_len = base64_encode(
            request_buf, request_stream.bytes_written, 
            request_b64_buf, sizeof(request_b64_buf));
    if (request_b64_len < 0) {
        printf("base64_encode failed (%d)\n", request_b64_len);
        qemu_exit();
    }

    printf("request:\n");
    xxd(request_b64_buf, request_b64_len);

    // POST challenge
    // TODO get from policy.h
    printf("connecting to %s:%d...\n",
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT);
    ssize_t pat_len = http_post(
            VERACRUZ_SERVER_HOST,
            VERACRUZ_SERVER_PORT,
            "/sinaloa",
            request_b64_buf,
            request_b64_len,
            buffer,
            sizeof(buffer));
    if (pat_len < 0) {
        printf("http_post failed (%d)\n", pat_len);
        qemu_exit();
    }

    printf("http_post -> %d\n", pat_len);
    printf("attest: challenge response:\n");
    xxd(buffer, pat_len);

    // forward to proxy attestation server
    printf("connecting to %s:%d...\n",
            PROXY_ATTESTATION_SERVER_HOST,
            PROXY_ATTESTATION_SERVER_PORT);
    ssize_t res = http_post(
            PROXY_ATTESTATION_SERVER_HOST,
            PROXY_ATTESTATION_SERVER_PORT,
            "/VerifyPAT",
            buffer,
            pat_len,
            buffer2,
            sizeof(buffer2));
    if (res < 0) {
        printf("http_post failed (%d)\n", res);
        qemu_exit();
    }

    printf("http_post -> %d\n", res);
    printf("attest: PAT response:\n");
    xxd(buffer2, res);

    // back to buffer1, TODO in-place base64?
    // TODO use strnlen...
    ssize_t verif_len = base64_decode(buffer2, buffer, sizeof(buffer));
    if (verif_len < 0) {
        printf("base64_decode failed (%d)\n", verif_len);
        qemu_exit();
    }
    
    printf("attest: PAT decoded response:\n");
    xxd(buffer, res);

    if (verif_len < 131) {
        printf("pat response too small\n");
        qemu_exit();
    }

    // check that challenge matches
    if (memcmp(challenge, &buffer[8], 32) != 0) {
        printf("challenge mismatch\n");
        printf("expected: ");
        for (int i = 0; i < sizeof(challenge); i++) {
            printf("%02x", challenge[i]);
        }
        printf("\n");
        printf("recieved: ");
        for (int i = 0; i < 32; i++) {
            printf("%02x", buffer[8+i]);
        }
        printf("\n");
        qemu_exit();
    }

    // TODO check these against policy
    printf("enclave hash:\n");
    xxd(&buffer[47], 32);
    printf("enclave cert hash:\n");
    xxd(&buffer[86], 32);
    printf("enclave name: %.*s\n", 7, &buffer[124]);

//
//    for (int i = 0; i < res; i++) {
//        if (buffer[i] != '\r') {
//            printf("%c", buffer[i]);
//        }
//    }
//    printf("\n");

//
//	while (1) {
//		int len = recv(sock, response, sizeof(response) - 1, 0);
//
//		if (len < 0) {
//			printf("Error reading response\n");
//			return;
//		}
//
//		if (len == 0) {
//			break;
//		}
//
//		response[len] = 0;
//		printf("%s", response);
//	}
//
//	printf("\n");
//
//
//	static struct addrinfo hints;
//	struct addrinfo *res;
//	int st, sock;
//
//#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
//	tls_credential_add(CA_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
//			   ca_certificate, sizeof(ca_certificate));
//#endif
//
//	printf("Preparing HTTP GET request for http://" HTTP_HOST
//	       ":" HTTP_PORT HTTP_PATH "\n");
//
//	hints.ai_family = AF_INET;
//	hints.ai_socktype = SOCK_STREAM;
//	st = getaddrinfo(HTTP_HOST, HTTP_PORT, &hints, &res);
//	printf("getaddrinfo status: %d\n", st);
//
//	if (st != 0) {
//		printf("Unable to resolve address, quitting\n");
//		return;
//	}
//
//#if 0
//	for (; res; res = res->ai_next) {
//		dump_addrinfo(res);
//	}
//#endif
//
//	dump_addrinfo(res);
//
//#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
//	sock = socket(res->ai_family, res->ai_socktype, IPPROTO_TLS_1_2);
//#else
//	sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
//#endif
//	CHECK(sock);
//	printf("sock = %d\n", sock);
//
//#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
//	sec_tag_t sec_tag_opt[] = {
//		CA_CERTIFICATE_TAG,
//	};
//	CHECK(setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST,
//			 sec_tag_opt, sizeof(sec_tag_opt)));
//
//	CHECK(setsockopt(sock, SOL_TLS, TLS_HOSTNAME,
//			 HTTP_HOST, sizeof(HTTP_HOST)))
//#endif
//
//	CHECK(connect(sock, res->ai_addr, res->ai_addrlen));
//	CHECK(send(sock, REQUEST, SSTRLEN(REQUEST), 0));
//
//	printf("Response:\n\n");
//
//	while (1) {
//		int len = recv(sock, response, sizeof(response) - 1, 0);
//
//		if (len < 0) {
//			printf("Error reading response\n");
//			return;
//		}
//
//		if (len == 0) {
//			break;
//		}
//
//		response[len] = 0;
//		printf("%s", response);
//	}
//
//	printf("\n");
//
//	(void)close(sock);
    qemu_exit();
}
