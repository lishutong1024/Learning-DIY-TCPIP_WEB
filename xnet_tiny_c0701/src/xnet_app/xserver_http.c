#include "xserver_http.h"
#include <string.h>
#include <stdio.h>

static xtcp_t * curr_http = (xtcp_t *)0;
static char rx_buffer[1024], tx_buffer[1024];
static char url_path[255], file_path[255];

static int get_line(char *buf, int size) {
    int i = 0;

    while ((i < size) && curr_http) {
        char c;

        if (xtcp_read(curr_http, (uint8_t *)&c, 1) > 0) {
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

static int http_send(char* buf, int size) {
    int sended_size = 0;

    while ((size > 0) && curr_http) {
        uint16_t curr_size = xtcp_write(curr_http, (uint8_t*)buf, (uint16_t)size);
        size -= curr_size;
        buf += curr_size;
        sended_size += curr_size;

        xnet_poll();
    }
    return sended_size;
}

static void close_http(void) {
    if (curr_http) {
        xtcp_close(curr_http);
        curr_http = (xtcp_t*)0;
    }
    printf("http closed.\n");
}

static void send_404_not_found(void) {
    sprintf(tx_buffer, "HTTP/1.0 404 NOT FOUND\r\nContent-Type: text/html\r\n");
    http_send(tx_buffer, strlen(tx_buffer));
}

static void send_400_bad_request(void) {
    sprintf(tx_buffer, "HTTP/1.0 400 BAD REQUEST\r\nContent-type: text/html\r\n");
    http_send(tx_buffer, strlen(tx_buffer));
}

static void send_file (const char * url) {
    int is_html = 0;
    FILE * file;
    uint32_t size;

    while (*url == '/') url++;
    sprintf(file_path, "%s/%s", XHTTP_DOC_DIR, url);

    if (strstr(url_path, ".html") || strstr(url_path, ".htm")) {
        is_html = 1;
    }

    file = fopen(file_path, is_html ? "r" : "rb");
    if (file == NULL) {
        send_404_not_found();
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
        (int)size, is_html ? "text/html" : "image/jpeg");
    http_send(tx_buffer, strlen(tx_buffer));

    if (is_html) {
        while (!feof(file)) {
            fgets(tx_buffer, sizeof(tx_buffer), file);
            if (http_send(tx_buffer, strlen(tx_buffer)) <= 0) return;
        }
    } else {
        while (!feof(file)) {
            size = fread(tx_buffer, 1, sizeof(tx_buffer), file);
            if (http_send(tx_buffer, size) <= 0) return;
        }
    }
    fclose(file);
}

static xnet_err_t http_handler (xtcp_t* tcp, xtcp_conn_state_t state) {
    if (state == XTCP_STATE_CLOSED) {
        close_http();
    } else if (state == XTCP_CONN_CONNECTED) {
        curr_http = tcp;
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
    if (curr_http && get_line(rx_buffer, sizeof(rx_buffer)) > 0) {
        int i;
        char* c = rx_buffer;

        while (*c == ' ') c++;      // 跳过空格
        if (strncmp(rx_buffer, "GET", 3) != 0) {
            // send_400_bad_request();
            close_http();
            return;
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
        send_file(url_path);
        close_http();
    }
}
