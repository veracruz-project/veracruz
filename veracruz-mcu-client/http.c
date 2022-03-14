/*
 * HTTP convenience functions, these just wrap the low-level HTTP API
 * that Zephyr provides
 *
 * ## Authors
 *
 * The Veracruz Development Team.
 *
 * ## Licensing and copyright notice
 *
 * See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
 * information on licensing and copyright.
 *
 */

#include "http.h"
#include "vc.h"

#include <net/socket.h>
#include <net/http_client.h>


// a struct to maintain the state of the current HTTP request
struct http_get_state {
    uint8_t *buf;
    size_t buf_len;
    size_t pos;
};

// HTTP GET callback, this is call by Zephyr's networking stack
static void http_get_cb(
        struct http_response *rsp,
        enum http_final_call final,
        void *udata) {
    struct http_get_state *state = udata;
    uint8_t *start = (rsp->body_start) ? rsp->body_start : rsp->recv_buf;
    size_t len = rsp->processed - state->pos;

    if (state->pos + len > state->buf_len) {
        VC_LOGLN("http get buffer overflow! truncating (%d > %d)",
            state->pos + len, state->buf_len);

        len = state->buf_len - state->pos;
    }

    memcpy(&state->buf[state->pos], start, len);
    state->pos += len;
}

// HTTP GET operation
//
// - host     Hostname or url of server to access
// - port     Port of server to access
// - path     Path on the server to access
// - buf      Buffer to write response into
// - buf_len  Size of response buffer in bytes
//
// Returns the number of bytes recieved, or a negative error code
ssize_t http_get(
        const char *host,
        uint16_t port,
        const char *path,
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
        VC_LOGLN("http malloc failed (-ENOMEM)");
        return -ENOMEM;
    }

    // create socket and connect to server
    // TODO IPv6? can use net_sin(addr)->sin_family here
    // DNS? Take in a string more useful API?
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        VC_LOGLN("http socket open failed (%d)", -errno);
        free(pbuf);
        return -errno;
    }

    int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0) {
        VC_LOGLN("http connect failed (%d)", -errno);
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
        VC_LOGLN("http req failed (%d)", err);
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
//
// - host             Hostname or url of server to access
// - port             Port of server to access
// - path             Path on the server to access
// - payload_buf      Buffer of data to send with POST message
// - payload_buf_len  Size of payload buffer in bytes
// - resp_buf         Buffer to write response into
// - resp_buf_len     Size of response buffer in bytes
//
// Returns the number of bytes recieved, or a negative error code
ssize_t http_post(
        const char *host,
        uint16_t port,
        const char *path,
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
        VC_LOGLN("http malloc failed (-ENOMEM)");
        return -ENOMEM;
    }

    // create socket and connect to server
    // TODO IPv6? can use net_sin(addr)->sin_family here
    // DNS? Take in a string more useful API?
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        VC_LOGLN("http socket open failed (%d)", -errno);
        free(pbuf);
        return -errno;
    }

    int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0) {
        VC_LOGLN("http connect failed (%d)", -errno);
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
        VC_LOGLN("http req failed (%d)", err);
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

