/**
 * 用1500行代码从0开始实现TCP/IP协议栈+WEB服务器
 *
 * 本源码旨在用最简单、最易懂的方式帮助你快速地了解TCP/IP以及HTTP工作原理的主要核心知识点。
 * 所有代码经过精心简化设计，避免使用任何复杂的数据结构和算法，避免实现其它无关紧要的细节。
 *
 * 本源码配套高清的视频教程，免费提供下载！具体的下载网址请见下面。
 * 视频中的PPT不提供下载，但配套了学习指南，请访问下面的网址。
 *
 * 作者：李述铜
 * 网址: http://01ketang.cc/tcpip
 * QQ群：524699753（加群时请注明：tcpip），免费提供关于该源码的支持和问题解答。
 * 微信公众号：请搜索 01课程
 *
 * 版权声明：源码仅供学习参考，请勿用于商业产品，不保证可靠性。二次开发或其它商用前请联系作者。
 * 注：
 * 1.源码不断升级中，该版本可能非最新版。如需获取最新版，请访问上述网址获取最新版本的代码
 * 2.1500行代码指未包含注释的代码。
 */
#include "xserver_http.h"
#include <string.h>
#include <stdio.h>

static char rx_buffer[1024], tx_buffer[1024];
static char url_path[255], file_path[255];

#define XTCP_FIFO_SIZE      40

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
        int curr_size = xtcp_write(tcp, (uint8_t*)buf, (uint16_t)size);
        if (curr_size < 0) break;
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

struct xhttp_file_type_t {
    const char * ext_name;
    const char * content_type;
};

// 请参考以下链接
// https://www.runoob.com/http/http-content-type.html
const struct xhttp_file_type_t file_type_table[] = {
        {".html", "text/html"},
        {".bmp", "application/x-bmp"},
        {".gif", "image/gif"},
        {".ico", "image/x-icon"},
        {".jpeg", "image/jpeg"},
        {".css", "text/css"},
        {".jpg", "image/jpeg"},
        {".js", "application/x-javascript"},
        {".png", "image/png"},
};

static void send_file (xtcp_t * tcp, const char * url) {
    FILE * file;
    uint32_t size;
    const char * content_type = "text/html";
    int i;

    while (*url == '/') url++;
    sprintf(file_path, "%s/%s", XHTTP_DOC_DIR, url);

    for (i = 0; i < sizeof(file_type_table) / sizeof(struct xhttp_file_type_t); i++) {
        if (strstr(url_path, file_type_table[i].ext_name)) {
            content_type = file_type_table[i].content_type;
            break;
        }
    }

    file = fopen(file_path, "rb");
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
        "Connection:close\r\n"
        "Pragma:no-cache\r\n"
        "Content-Type:%s\r\n\r\n",
        (int)size, content_type);
    http_send(tcp, tx_buffer, strlen(tx_buffer));


        while (!feof(file)) {
            size = fread(tx_buffer, 1, sizeof(tx_buffer), file);
            if (http_send(tcp, tx_buffer, size) <= 0) return;
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
