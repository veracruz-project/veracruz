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
#include <kernel.h>

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
//#define HTTP_PORT "443"
//#else
////#define HTTP_PORT "80"
//#define HTTP_PORT "3017"
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

#ifndef HTTP_SERVER
#define HTTP_SERVER "172.17.0.2"
#endif

#ifndef HTTP_PORT
#define HTTP_PORT 3017
#endif

static void http_get_cb(
        struct http_response *rsp,
        enum http_final_call state,
        void *udata) {
    // TODO probably handle this?
    if (state != HTTP_DATA_MORE) {
        printf("http rsp state != HTTP_DATA_FINAL (%d), "
            "should handle this\n", state);
    }

    printf("rsp = %s (%d bytes)\n", rsp->http_status, rsp->data_len);
}

// TODO TLS? https_get?
int http_get(
        struct sockaddr *server_addr,
        socklen_t server_addr_len,
        // TODO dedup this?
        const char *host,
        const char *path,
        // TODO headers?
        uint8_t *buf,
        size_t buf_size,
        int32_t timeout) {
    // create socket and connect to server
    // TODO IPv6? can use net_sin(addr)->sin_family here
    // DNS? Take in a string more useful API?
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        printf("http socket open failed (%d)\n", -errno);
        return -errno;
    }

    int res = connect(sock, server_addr, server_addr_len);
    if (res < 0) {
        printf("http connect failed (%d)\n", -errno);
        return -errno;
    }

    // perform client request, Zephyr handles most of this for us
    struct http_request req;
    memset(&req, 0, sizeof(req));
    req.method = HTTP_GET;
    req.url = path;
    req.host = host;
    req.protocol = "HTTP/1.1";
    req.response = http_get_cb;
    req.recv_buf = buf;
    req.recv_buf_len = buf_size;

    int err = http_client_req(sock, &req, timeout, NULL);
    if (err < 0) {
        printf("http req failed (%d)\n", err);
        return err;
    }

    // done, close
    close(sock);
    return 0;
}

uint8_t buffer[1024];

// hack to exit QEMU
//__attribute__((noreturn))
void qemu_exit(void) {
    __asm__ volatile (
        "mov r0, #0x18 \n\t"
        "ldr r1, =#0x20026 \n\t"
        "bkpt #0xab \n\t"
    );
}

void main(void)
{
    // setup address, TODO use DNS?
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(HTTP_PORT);
    inet_pton(AF_INET, HTTP_SERVER, &addr.sin_addr);

    // perform GET
    printf("connecting to %s:%d...\n", HTTP_SERVER, HTTP_PORT);
    int err = http_get(
            (struct sockaddr*)&addr,
            sizeof(addr),
            HTTP_SERVER,
            "/",
            buffer,
            sizeof(buffer),
            3000);
    if (err) {
        printf("http_get failed (%d)\n", err);
        qemu_exit();
    }

    printf("get worked?");
    printf("%s", buffer);
    printf("\n");
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
