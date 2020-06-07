/**
 * 用1500行代码从0开始实现TCP/IP协议栈+WEB服务器
 *
 * 本源码旨在用最简单、最易懂的方式帮助你快速地了解TCP/IP以及HTTP工作原理的主要核心知识点。
 * 所有代码经过精心简化设计，避免使用任何复杂的数据结构和算法，避免实现其它无关紧要的细节。
 *
 * 本源码配套高清的视频教程，免费提供下载！具体的下载网址请见下面。
 * 视频中的PPT暂时提供下载，但配套了学习指南，请访问下面的网址。
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
 *
 * 如果你在学习本课程之后，对深入研究TCP/IP感兴趣，欢迎关注我的后续课程。我将开发出一套更加深入
 * 详解TCP/IP的课程。采用多线程的方式，实现更完善的功能，包含但不限于
 * 1. IP层的分片与重组
 * 2. Ping功能的实现
 * 3. TCP的流量控制等
 * 4. 基于UDP的TFTP服务器实现
 * 5. DNS域名接触
 * 6. DHCP动态地址获取
 * 7. HTTP服务器
 * ..... 更多功能开发中...........
 * 如果你有兴趣的话，欢迎关注。
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

static xnet_err_t http_handler (xtcp_t* tcp, xtcp_conn_state_t state) {
    if (state == XTCP_CONN_CONNECTED) {
        xhttp_fifo_in(&http_fifo, tcp);
        printf("http conntected.\n");
    } else if (state == XTCP_CONN_CLOSED) {
        printf("http closed.\n");
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
