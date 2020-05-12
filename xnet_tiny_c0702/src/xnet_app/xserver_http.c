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

static int get_line(xtcp_t * tcp, char *buf, int size) {
    int i = 0;

    while (i < size) {
        char c;

        if (xtcp_read(tcp, (uint8_t *)&c, 1) > 0) {
            if ((c != '\n') && (c != '\r')) {
                buf[i++] = c;
            } else if (c == '\n') {
                break;
            }
        }
        xnet_poll();
    }
    buf[i] = '\0';
    return i;
}

static int http_send(xtcp_t * tcp, char* buf, int size) {
    int sended_size = 0;

    while (size > 0) {
        uint16_t curr_size = xtcp_write(tcp, (uint8_t*)buf, (uint16_t)size);
        size -= curr_size;
        buf += curr_size;
        sended_size += curr_size;

        xnet_poll();
    }
    return sended_size;
}

static void close_http(xtcp_t * tcp) {
    xtcp_close(tcp);
    printf("http closed.\n");
}

static void send_404_not_found(xtcp_t * tcp) {
    sprintf(tx_buffer, "HTTP/1.0 404 NOT FOUND\r\n"
                       "Content-Type: text/html\r\n"
                       "\r\n404 not found");
    http_send(tcp, tx_buffer, strlen(tx_buffer));
}

static void send_400_bad_request(xtcp_t * tcp) {
    sprintf(tx_buffer, "HTTP/1.0 400 BAD REQUEST\r\n"
                       "Content-type: text/html\r\n"
                       "\r\n400 bad request");
    http_send(tcp, tx_buffer, strlen(tx_buffer));
}

static void send_file (xtcp_t * tcp, const char * url) {
    int is_text = 0;
    FILE * file;
    uint32_t size;
    static char * text_file[] = {".html", ".css", ".js", "txt"};
    int i;

    while (*url == '/') url++;
    sprintf(file_path, "%s/%s", XHTTP_DOC_DIR, url);

    for (i = 0; i < sizeof(text_file) / sizeof(char *); i++) {
        if (strstr(url_path, text_file[i])) {
            is_text = 1;
            break;
        }
    }

    file = fopen(file_path, is_text ? "r" : "rb");
    if (file == NULL) {
        send_404_not_found(tcp);
        return;
    }

    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    sprintf(tx_buffer,
        "HTTP/1.0 200 OK\r\n"
        "Server: TINY HTTP SERVER/1.0\r\n"
        "Content-Length:%d\r\n"
        "Pragma:no-cache\r\n"
        "Content-Type:%s\r\n\r\n",
        (int)size, is_text ? "text/html" : "image/jpeg");
    http_send(tcp, tx_buffer, strlen(tx_buffer));

    if (is_text) {
        while (!feof(file)) {
            fgets(tx_buffer, sizeof(tx_buffer), file);
            if (http_send(tcp, tx_buffer, strlen(tx_buffer)) <= 0) return;
        }
    } else {
        while (!feof(file)) {
            size = fread(tx_buffer, 1, sizeof(tx_buffer), file);
            if (http_send(tcp, tx_buffer, size) <= 0) return;
        }
    }
    fclose(file);
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
    xtcp_t * tcp;

    while ((tcp = http_fifo_out(&http_fifo)) != (xtcp_t *)0) {
        int i;
        char* c = rx_buffer;

        if (get_line(tcp, rx_buffer, sizeof(rx_buffer)) <= 0) {
            close_http(tcp);
            continue;
        }

        while (*c == ' ') c++;      // 跳过空格
        if (strncmp(rx_buffer, "GET", 3) != 0) {
            send_400_bad_request(tcp);
            close_http(tcp);
            continue;
        }

        while (*c != ' ') c++;      // 跳过GET字符
        while (*c == ' ') c++;      // 跳过空格
        for (i = 0; i < sizeof(url_path); i++) {
            if ((*c == '\0') || (*c == ' ')) break;
            url_path[i] = *c++;
        }

        url_path[i] = '\0';
        if (url_path[strlen(url_path) - 1] == '/') {
            strcat(url_path, "index.html");
        }

        // 发送文件
        send_file(tcp, url_path);

        // 关掉服务器
        close_http(tcp);
    }
}
