/**
 * 本源码配套的课程为 - 自己动手写TCIP/IP协议栈 源码
 * 作者：李述铜
 * 课程网址：http://01ketang.cc
 * 版权声明：本源码非开源，二次开发，或其它商用前请联系作者。
 * 注：源码不断升级中，该版本可能非最新版。如需获取最新版，请联系作者。
 */
#include "xserver_datetime.h"
#include <string.h>
#include <time.h>

#define TIME_STR_SIZE       128         // 时间字符串存储长度

static xnet_err_t datetime_handler (xudp_t * udp, xipaddr_t * src_ip, uint16_t src_port, xnet_packet_t * packet) {
    xnet_err_t err;
    xnet_packet_t * tx_packet;
    time_t rawtime;
    const struct tm * timeinfo;
    size_t str_size;

    tx_packet = xnet_alloc_for_send(TIME_STR_SIZE);
    if (tx_packet == (xnet_packet_t *)0) {
        return XNET_ERR_MEM;
    }

    // 参见：http://www.cplusplus.com/reference/ctime/localtime/
    time (&rawtime);
    timeinfo = localtime (&rawtime);

    // strftime参见：http://www.cplusplus.com/reference/ctime/strftime/
    // Weekday, Month Day, Year Time-Zone
    str_size = strftime((char *)tx_packet->data, TIME_STR_SIZE, "%A, %B %d, %Y %T-%z", timeinfo);
    tx_packet->data[str_size] = '\0';

    err = xudp_out(udp, src_ip, src_port, tx_packet);
    if (err < 0) {
        return err;
    }

    return XNET_ERR_OK;
}

xnet_err_t xserver_datetime_create(uint16_t port) {
    xnet_err_t err;

    xudp_t* udp = xudp_open(datetime_handler);
    if (udp == (xudp_t*)0) {
        return -1;
    }

    err = xudp_bind(udp, port);
    if (err < 0) {
        xudp_close(udp);
        return err;
    }
    return 0;
}
