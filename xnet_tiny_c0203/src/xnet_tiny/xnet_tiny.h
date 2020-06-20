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
 * 微信公众号：请搜索 01课堂
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
#ifndef XNET_TINY_H
#define XNET_TINY_H

#include <stdint.h>

#define XNET_CFG_NETIF_IP               {192, 168, 254, 2}  // 本机网卡IP
#define XNET_CFG_PACKET_MAX_SIZE        1516        // 收发数据包的最大大小
#define XARP_CFG_ENTRY_OK_TMO	        (5 * 1000)         // ARP表项超时时间
#define XARP_CFG_ENTRY_PENDING_TMO	    (1 * 1000)          // ARP表项挂起超时时间
#define XARP_CFG_MAX_RETRIES		    4                   // ARP表挂起时重试查询次数

#pragma pack(1)

#define XNET_IPV4_ADDR_SIZE             4           // IP地址长度
#define XNET_MAC_ADDR_SIZE              6           // MAC地址长度

/**
 * 以太网数据帧格式：RFC894
 */
typedef struct _xether_hdr_t {
    uint8_t dest[XNET_MAC_ADDR_SIZE];           // 目标mac地址
    uint8_t src[XNET_MAC_ADDR_SIZE];            // 源mac地址
    uint16_t protocol;                          // 协议/长度
}xether_hdr_t;

#define XARP_HW_ETHER               0x1         // 以太网
#define XARP_REQUEST                0x1         // ARP请求包
#define XARP_REPLY                  0x2         // ARP响应包

typedef struct _xarp_packet_t {
    uint16_t hw_type, pro_type;                 // 硬件类型和协议类型
    uint8_t hw_len, pro_len;                    // 硬件地址长 + 协议地址长
    uint16_t opcode;                            // 请求/响应
    uint8_t sender_mac[XNET_MAC_ADDR_SIZE];     // 发送包硬件地址
    uint8_t sender_ip[XNET_IPV4_ADDR_SIZE];     // 发送包协议地址
    uint8_t target_mac[XNET_MAC_ADDR_SIZE];     // 接收方硬件地址
    uint8_t target_ip[XNET_IPV4_ADDR_SIZE];     // 接收方协议地址
}xarp_packet_t;

#pragma pack()

typedef enum _xnet_err_t {
    XNET_ERR_OK = 0,
    XNET_ERR_IO = -1,
    XNET_ERR_NONE = -2,
}xnet_err_t;

/**
 * 网络数据结构
 */
typedef struct _xnet_packet_t{
    uint16_t size;                              // 包中有效数据大小
    uint8_t * data;                             // 包的数据起始地址
    uint8_t payload[XNET_CFG_PACKET_MAX_SIZE];  // 最大负载数据量
}xnet_packet_t;

typedef uint32_t xnet_time_t;           // 时间类型，返回当前系统跑了多少个100ms
const xnet_time_t xsys_get_time(void);
int xnet_check_tmo(xnet_time_t* time, uint32_t ms);

xnet_packet_t * xnet_alloc_for_send(uint16_t data_size);
xnet_packet_t * xnet_alloc_for_read(uint16_t data_size);

xnet_err_t xnet_driver_open (uint8_t * mac_addr);
xnet_err_t xnet_driver_send (xnet_packet_t * packet);
xnet_err_t xnet_driver_read (xnet_packet_t ** packet);

typedef enum _xnet_protocol_t {
    XNET_PROTOCOL_ARP = 0x0806,     // ARP协议
    XNET_PROTOCOL_IP = 0x0800,      // IP协议
}xnet_protocol_t;

/**
 * IP地址
 */
typedef union _xipaddr_t {
    uint8_t array[XNET_IPV4_ADDR_SIZE];     // 以数据形式存储的ip
    uint32_t addr;                          // 32位的ip地址
}xipaddr_t;

#define XARP_ENTRY_FREE		        0       // ARP表项空闲
#define XARP_ENTRY_OK		        1       // ARP表项解析成功
#define XARP_ENTRY_RESOLVING	    2       // ARP表项正在解析
#define XARP_TIMER_PERIOD           1000    // ARP扫描周期，1s足够

/**
 * ARP表项
 */
typedef struct _xarp_entry_t {
    xipaddr_t ipaddr;                       // ip地址
    uint8_t	macaddr[XNET_MAC_ADDR_SIZE];    // mac地址
    uint8_t	state;                          // 状态位
    uint16_t tmo;                           // 当前超时
    uint8_t	retry_cnt;                      // 当前重试次数
}xarp_entry_t;

void xarp_init(void);
xnet_err_t xarp_make_request(const xipaddr_t * ipaddr);
void xarp_in(xnet_packet_t * packet);
int xarp_find(const xipaddr_t* ipaddr, uint8_t** mac_addr);
int xarp_resolve(const xipaddr_t * ipaddr, uint8_t ** mac_addr);
void xarp_poll(void);

void xnet_init (void);
void xnet_poll(void);

#endif // XNET_TINY_H

