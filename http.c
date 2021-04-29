/*
 * HTTP convenience functions, these just wrap the low-level HTTP API
 * that Zephyr provides
 *
 */

#include "http.h"

#include <net/socket.h>
#include <net/http_client.h>


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

//    printf("rsp = %s (%d bytes)\n", rsp->http_status, rsp->data_len);

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

// HTTP GET operation
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

    int err = http_client_req(sock, &req, HTTP_TIMEOUT, &state);
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

// HTTP POST operation
// TODO deduplicate?
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

    int err = http_client_req(sock, &req, HTTP_TIMEOUT, &state);
    if (err < 0) {
        printf("http req failed (%d)\n", err);
        free(pbuf);
        close(sock);
        return err;
    }

    // done, close
    free(pbuf);
    close(sock);

    // There is some sort of overrun in the network stack, sleeping here
    // briefly avoids issues
    k_sleep(Z_TIMEOUT_MS(100));
    
    return state.pos;
}

