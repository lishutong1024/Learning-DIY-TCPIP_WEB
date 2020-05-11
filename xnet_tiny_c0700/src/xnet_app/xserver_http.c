#include "xserver_http.h"
#include <string.h>
#include <stdio.h>

static xtcp_t * curr_http = (xtcp_t *)0;

static void close_http(void) {
    if (curr_http) {
        xtcp_close(curr_http);
        curr_http = (xtcp_t*)0;
    }
    printf("http closed.\n");
}

static xnet_err_t http_handler (xtcp_t* tcp, xtcp_conn_state_t state) {
    if (state == XTCP_CONN_CLOSED) {
        close_http();
    } else if (state == XTCP_CONN_CONNECTED) {
        curr_http = tcp;
        printf("http conntected.\n");
    }
    return XNET_ERR_OK;
}

xnet_err_t xserver_http_create(uint16_t port) {
    xnet_err_t err;

    xtcp_t * tcp = xtcp_open(http_handler);
    if (!tcp) return XNET_ERR_MEM;
    err = xtcp_bind(tcp, port);       // HTTP熟知端口
    if (err < 0) return  err;
    return xtcp_listen(tcp);
}

void xserver_http_run(void) {

}
