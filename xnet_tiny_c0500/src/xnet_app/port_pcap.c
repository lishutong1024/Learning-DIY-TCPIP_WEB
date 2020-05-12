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
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "pcap_device.h"
#include "xnet_tiny.h"

static pcap_t * pcap;

// pcap所用的网卡
const char * ip_str = "192.168.254.1";      // 根据实际电脑上存在的网卡地址进行修改
const char my_mac_addr[] = {0xF0, 0x4D, 0xA2, 0xF9, 0xE6, 0x77};

/**
 * 初始化网络驱动
 * @return 0成功，其它失败
 */
xnet_err_t xnet_driver_open (uint8_t * mac_addr) {
    memcpy(mac_addr, my_mac_addr, sizeof(my_mac_addr));
    pcap = pcap_device_open(ip_str, mac_addr, 1);
    if (pcap == (pcap_t *)0) {
        exit(-1);
    }
    return XNET_ERR_OK;
}

/**
 * 发送数据
 * @param frame 数据起始地址
 * @param size 数据长度
 * @return 0 - 成功，其它失败
 */
xnet_err_t xnet_driver_send (xnet_packet_t * packet) {
    return pcap_device_send(pcap, packet->data, packet->size);
}

/**
 * 读取数据
 * @param frame 数据存储位置
 * @param size 数据长度
 * @return 0 - 成功，其它失败
 */
xnet_err_t xnet_driver_read (xnet_packet_t ** packet) {
    uint16_t size;
    xnet_packet_t * r_packet = xnet_alloc_for_read(XNET_CFG_PACKET_MAX_SIZE);

    size = pcap_device_read(pcap, r_packet->data, XNET_CFG_PACKET_MAX_SIZE);
    if (size) {
        r_packet->size = size;
        *packet = r_packet;
        return XNET_ERR_OK;
    }

    return XNET_ERR_IO;
}

/**
 * 获取自程序启动以来，过去了多长时间
 * @return 程序的系统时间
 */
const xnet_time_t xsys_get_time(void) {
    static uint32_t pre = 0;

    // 以下部分仅供调试时使用
#if 0
    uint32_t c = clock() / CLOCKS_PER_SEC;
    if (c != pre) {
        printf("sec: %d, 100ms: %d\n", c, (xnet_time_t)(clock()  * 10 / CLOCKS_PER_SEC));
        pre = c;
    }
#endif
    return (xnet_time_t)(clock()  * 10 / CLOCKS_PER_SEC);
}