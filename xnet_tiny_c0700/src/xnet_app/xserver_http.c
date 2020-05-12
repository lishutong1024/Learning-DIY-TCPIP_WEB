#include "xserver_http.h"
#include <string.h>
#include <stdio.h>

static char rx_buffer[1024], tx_buffer[1024];
static char url_path[255], file_path[255];

#define XTCP_FIFO_SIZE      20

typedef struct _xhttp_fifo_t {
    xtcp_t * buffer[XTCP_FIFO_SIZE];
    uint8_t front, tail, count;
}xhttp_fifo_t;

static xhttp_fifo_t http_fifo;

static void xhttp_fifo_init(xhttp_fifo_t * fifo) {
    fifo->count = 0;
    fifo->front = fifo->tail = 0;
}

static xnet_err_t xhttp_fifo_in(xhttp_fifo_t * fifo, xtcp_t * tcp) {
    if (fifo->count >= XTCP_FIFO_SIZE) {
        return XNET_ERR_MEM;
    }

    fifo->buffer[fifo->front++] = tcp;
    if (fifo->front >= XTCP_FIFO_SIZE) {
        fifo->front = 0;
    }
    fifo->count++;
    return XNET_ERR_OK;
}

static xtcp_t * http_fifo_out(xhttp_fifo_t * fifo) {
    xtcp_t * tcp;

    if (fifo->count == 0) {
        return (xtcp_t *)0;
    }

    tcp = fifo->buffer[fifo->tail++];
    if (fifo->tail >= XTCP_FIFO_SIZE) {
        fifo->tail = 0;
    }
    fifo->count--;
    return tcp;
}

static xnet_err_t http_handler (xtcp_t* tcp, xtcp_conn_state_t state) {
    if (state == XTCP_CONN_CONNECTED) {
        xhttp_fifo_in(&http_fifo, tcp);
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

    xhttp_fifo_init(&http_fifo);
    return xtcp_listen(tcp);
}

void xserver_http_run(void) {

}
