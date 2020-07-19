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
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include "xnet_tiny.h"

#define min(a, b)               ((a) > (b) ? (b) : (a))
#define XTCP_DATA_MAX_SIZE       (XNET_CFG_PACKET_MAX_SIZE - sizeof(xether_hdr_t) - sizeof(xip_hdr_t) - sizeof(xtcp_hdr_t))
#define tcp_get_init_seq()      ((rand() << 16) + rand())

static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;
static const uint8_t ether_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];                   // mac地址
static xnet_packet_t tx_packet, rx_packet;                      // 接收与发送缓冲区
static xarp_entry_t arp_entry;                                  // 节省内存，只使用一个ARP表项
static xnet_time_t arp_timer;                                   // ARP扫描定时
static xudp_t udp_socket[XUDP_CFG_MAX_UDP];                     // UDP连接块
static xtcp_t tcp_socket[XTCP_CFG_MAX_TCP];                     // TCP连接块

static void update_arp_entry(uint8_t* src_ip, uint8_t* mac_addr);

#define swap_order16(v)   ((((v) & 0xFF) << 8) | (((v) >> 8) & 0xFF))
#define swap_order32(v)   ((((v >> 0) & 0xFF) << 24) | (((v >> 8) & 0xFF) << 16) | (((v >> 16) & 0xFF) << 8) | ((v >> 24) & 0xFF))
#define xipaddr_is_equal_buf(addr, buf)      (memcmp((addr)->array, (buf), XNET_IPV4_ADDR_SIZE) == 0)
#define xipaddr_is_equal(addr1, addr2)       ((addr1)->addr == (addr2)->addr)
#define xipaddr_from_buf(dest, buf)          ((dest)->addr = *(uint32_t *)(buf))

/**
 * 检查是否超时
 * @param time 前一时间
 * @param sec 预期超时时间，值为0时，表示获取当前时间
 * @return 0 - 未超时，1-超时
 */
int xnet_check_tmo(xnet_time_t * time, uint32_t sec) {
    xnet_time_t curr = xsys_get_time();
    if (sec == 0) {          // 0，取当前时间
        *time = curr;
        return 0;
    } else if (curr - *time >= sec) {   // 非0检查超时
        *time = curr;       // 当超时时，才更新时间
        return 1;
    }
    return 0;
}

/**
 * 分配一个网络数据包用于发送数据
 * @param data_size 数据空间大小
 * @return 分配得到的包结构
 */
xnet_packet_t * xnet_alloc_for_send(uint16_t data_size) {
    // 从tx_packet的后端往前分配，因为前边要预留作为各种协议的头部数据存储空间
    tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
    tx_packet.size = data_size;
    return &tx_packet;
}

/**
 * 分配一个网络数据包用于读取
 * @param data_size 数据空间大小
 * @return 分配得到的数据包
 */
xnet_packet_t * xnet_alloc_for_read(uint16_t data_size) {
    // 从最开始进行分配，用于最底层的网络数据帧读取
    rx_packet.data = rx_packet.payload;
    rx_packet.size = data_size;
    return &rx_packet;
}

/**
 * 为发包添加一个头部
 * @param packet 待处理的数据包
 * @param header_size 增加的头部大小
 */
static void add_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data -= header_size;
    packet->size += header_size;
}

/**
 * 为接收向上处理移去头部
 * @param packet 待处理的数据包
 * @param header_size 移去的头部大小
 */
static void remove_header(xnet_packet_t *packet, uint16_t header_size) {
    packet->data += header_size;
    packet->size -= header_size;
}

/**
 * 将包的长度截断为size大小
 * @param packet 待处理的数据包
 * @param size 最终大小
 */
void truncate_packet(xnet_packet_t *packet, uint16_t size) {
    packet->size = min(packet->size, size);
}

/**
 * 以太网初始化
 * @return 初始化结果
 */
static xnet_err_t ethernet_init (void) {
    xnet_err_t err = xnet_driver_open(netif_mac);
    if (err < 0) return err;

    // 开启抓包工具wireshark，能在窗口发现如下数据包抓取
    // 1	0.000000	Dell_f9:e6:77	Broadcast	ARP	42	ARP Announcement for 192.168.254.2
    return xarp_make_request(&netif_ipaddr);
}

/**
 * 发送一个以太网数据帧
 * @param protocol 上层数据协议，IP或ARP
 * @param mac_addr 目标网卡的mac地址
 * @param packet 待发送的数据包
 * @return 发送结果
 */
static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t *mac_addr, xnet_packet_t * packet) {
    xether_hdr_t* ether_hdr;

    // 添加头部
    add_header(packet, sizeof(xether_hdr_t));
    ether_hdr = (xether_hdr_t*)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
    ether_hdr->protocol = swap_order16(protocol);

    // 数据发送
    return xnet_driver_send(packet);
}

/**
 * 将IP数据包通过以太网发送出去
 * @param dest_ip 目标IP地址
 * @param packet 待发送IP数据包
 * @return 发送结果
 */
static xnet_err_t ethernet_out (xipaddr_t * dest_ip, xnet_packet_t * packet) {
    xnet_err_t err;
    uint8_t * mac_addr;

    if ((err = xarp_resolve(dest_ip, &mac_addr) == XNET_ERR_OK)) {
        return ethernet_out_to(XNET_PROTOCOL_IP, mac_addr, packet);
    }
    return err;
}

/**
 * 以太网数据帧输入输出
 * @param packet 待处理的包
 */
static void ethernet_in (xnet_packet_t * packet) {
    // 至少要比头部数据大
    if (packet->size <= sizeof(xether_hdr_t)) {
        return;
    }

    // 往上分解到各个协议处理
    xether_hdr_t* hdr = (xether_hdr_t*)packet->data;
    switch (swap_order16(hdr->protocol)) {
        case XNET_PROTOCOL_ARP:
            remove_header(packet, sizeof(xether_hdr_t));
            xarp_in(packet);
            break;
        case XNET_PROTOCOL_IP: {
            // 以下代码是从IP包头中提取IP地址，以及从以太网包头中提取mac地址
            // 然后用其更新ARP表
            xip_hdr_t *iphdr = (xip_hdr_t *) (packet->data + sizeof(xether_hdr_t));
            if (packet->size >= sizeof(xether_hdr_t) + sizeof(xip_hdr_t)) {
                if (memcmp(iphdr->dest_ip, &netif_ipaddr.array, XNET_IPV4_ADDR_SIZE) == 0) {
                    update_arp_entry(iphdr->src_ip, hdr->src);
                }
            }
            remove_header(packet, sizeof(xether_hdr_t));
            xip_in(packet);
            break;
        }
    }
}

/**
 * 查询网络接口，看看是否有数据包，有则进行处理
 */
static void ethernet_poll (void) {
    xnet_packet_t * packet;

    if (xnet_driver_read(&packet) == XNET_ERR_OK) {
        // 正常情况下，在此打个断点，全速运行
        // 然后在对方端ping 192.168.254.2，会停在这里
        ethernet_in(packet);
    }
}

/**
 * ARP初始化
 */
void xarp_init(void) {
    arp_entry.state = XARP_ENTRY_FREE;

    // 获取初始时间
    xnet_check_tmo(&arp_timer, 0);
}

/**
 * 查询ARP表项是否超时，超时则重新请求
 */
void xarp_poll(void) {
    if (xnet_check_tmo(&arp_timer, XARP_TIMER_PERIOD)) {
        switch (arp_entry.state) {
            case XARP_ENTRY_RESOLVING:
                if (--arp_entry.tmo == 0) {     // 重试完毕，回收
                    if (arp_entry.retry_cnt-- == 0) {
                        arp_entry.state = XARP_ENTRY_FREE;
                    } else {    // 继续重试
                        xarp_make_request(&arp_entry.ipaddr);
                        arp_entry.state = XARP_ENTRY_RESOLVING;
                        arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
                    }
                }
                break;
            case XARP_ENTRY_OK:
                if (--arp_entry.tmo == 0) {     // 超时，重新请求
                    xarp_make_request(&arp_entry.ipaddr);
                    arp_entry.state = XARP_ENTRY_RESOLVING;
                    arp_entry.tmo = XARP_CFG_ENTRY_PENDING_TMO;
                }
                break;
        }
    }
}

/**
 * 生成一个ARP响应
 * @param arp_packet 接收到的ARP请求包
 * @return 生成结果
 */
 xnet_err_t xarp_make_response(xarp_packet_t * arp_packet) {
    xarp_packet_t* response_packet;
    xnet_packet_t * packet = xnet_alloc_for_send(sizeof(xarp_packet_t));

    response_packet = (xarp_packet_t *)packet->data;
    response_packet->hw_type = swap_order16(XARP_HW_ETHER);
    response_packet->pro_type = swap_order16(XNET_PROTOCOL_IP);
    response_packet->hw_len = XNET_MAC_ADDR_SIZE;
    response_packet->pro_len = XNET_IPV4_ADDR_SIZE;
    response_packet->opcode= swap_order16(XARP_REPLY);
    memcpy(response_packet->target_mac, arp_packet->sender_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->target_ip, arp_packet->sender_ip, XNET_IPV4_ADDR_SIZE);
    memcpy(response_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(response_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);
}

/**
 * 产生一个ARP请求，请求网络指定ip地址的机器发回一个ARP响应
 * @param ipaddr 请求的IP地址
 * @return 请求结果
 */
xnet_err_t xarp_make_request(const xipaddr_t * ipaddr) {
    xarp_packet_t* arp_packet;
    xnet_packet_t * packet = xnet_alloc_for_send(sizeof(xarp_packet_t));

    arp_packet = (xarp_packet_t *)packet->data;
    arp_packet->hw_type = swap_order16(XARP_HW_ETHER);
    arp_packet->pro_type = swap_order16(XNET_PROTOCOL_IP);
    arp_packet->hw_len = XNET_MAC_ADDR_SIZE;
    arp_packet->pro_len = XNET_IPV4_ADDR_SIZE;
    arp_packet->opcode = swap_order16(XARP_REQUEST);
    memcpy(arp_packet->sender_mac, netif_mac, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->sender_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    memset(arp_packet->target_mac, 0, XNET_MAC_ADDR_SIZE);
    memcpy(arp_packet->target_ip, ipaddr->array, XNET_IPV4_ADDR_SIZE);
    return ethernet_out_to(XNET_PROTOCOL_ARP, ether_broadcast, packet);
}

/**
 * 解析指定的IP地址，如果不在ARP表项中，则发送ARP请求
 * @param ipaddr 查找的ip地址
 * @param mac_addr 返回的mac地址存储区
 * @return XNET_ERR_OK 查找成功，XNET_ERR_NONE 查找失败
 */
xnet_err_t xarp_resolve(const xipaddr_t * ipaddr, uint8_t ** mac_addr) {
    if ((arp_entry.state == XARP_ENTRY_OK) && xipaddr_is_equal(ipaddr, &arp_entry.ipaddr)) {
        *mac_addr = arp_entry.macaddr;
        return XNET_ERR_OK;
    }

    xarp_make_request(ipaddr);
    return XNET_ERR_NONE;
}

/**
 * 更新ARP表项
 * @param src_ip 源IP地址
 * @param mac_addr 对应的mac地址
 */
static void update_arp_entry(uint8_t * src_ip, uint8_t * mac_addr) {
    memcpy(arp_entry.ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE);
    memcpy(arp_entry.macaddr, mac_addr, 6);
    arp_entry.state = XARP_ENTRY_OK;
    arp_entry.tmo = XARP_CFG_ENTRY_OK_TMO;
    arp_entry.retry_cnt = XARP_CFG_MAX_RETRIES;
}

/**
 * ARP输入处理
 * @param packet 输入的ARP包
 */
void xarp_in(xnet_packet_t * packet) {
    if (packet->size >= sizeof(xarp_packet_t)) {
        xarp_packet_t * arp_packet = (xarp_packet_t *) packet->data;
        uint16_t opcode = swap_order16(arp_packet->opcode);

        // 包的合法性检查
        if ((swap_order16(arp_packet->hw_type) != XARP_HW_ETHER) ||
            (arp_packet->hw_len != XNET_MAC_ADDR_SIZE) ||
            (swap_order16(arp_packet->pro_type) != XNET_PROTOCOL_IP) ||
            (arp_packet->pro_len != XNET_IPV4_ADDR_SIZE)
            || ((opcode != XARP_REQUEST) && (opcode != XARP_REPLY))) {
            return;
        }

        // 只处理发给自己的请求或响应包
        if (!xipaddr_is_equal_buf(&netif_ipaddr, arp_packet->target_ip)) {
            return;
        }

        // 根据操作码进行不同的处理
        switch (swap_order16(arp_packet->opcode)) {
            case XARP_REQUEST:  // 请求，回送响应
                // 在对方机器Ping 自己，然后看wireshark，能看到ARP请求和响应
                // 接下来，很可能对方要与自己通信，所以更新一下
                xarp_make_response(arp_packet);
                update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
                break;
            case XARP_REPLY:    // 响应，更新自己的表
                update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
                break;
        }
    }
}

/**
 * 校验和计算
 * @param buf 校验数据区的起始地址
 * @param len 数据区的长度，以字节为单位
 * @param pre_sum 累加的之前的值，用于多次调用checksum对不同的的数据区计算出一个校验和
 * @param complement 是否对累加和的结果进行取反
 * @return 校验和结果
 */
static uint16_t checksum16(uint16_t * buf, uint16_t len, uint16_t pre_sum, int complement) {
    uint32_t checksum = pre_sum;
    uint16_t high;

    while (len > 1) {
        checksum += *buf++;
        len -= 2;
    }
    if (len > 0) {
        checksum += *(uint8_t *)buf;
    }

    // 注意，这里要不断累加。不然结果在某些情况下计算不正确
    while ((high = checksum >> 16) != 0) {
        checksum = high + (checksum & 0xffff);
    }
    return complement ? (uint16_t)~checksum : (uint16_t)checksum;
}

/**
 * IP层的初始化
 */
void xip_init(void) {}

/**
 * IP层的输入处理
 * @param packet 输入的IP数据包
 */
void xip_in(xnet_packet_t * packet) {
    xip_hdr_t* iphdr = (xip_hdr_t*)packet->data;
    uint32_t total_size, header_size;
    uint16_t pre_checksum;
    xipaddr_t src_ip;

    // 进行一些必要性的检查：版本号要求
    if (iphdr->version != XNET_VERSION_IPV4) {
        return;
    }

    // 长度要求检查
    header_size = iphdr->hdr_len * 4;
    total_size = swap_order16(iphdr->total_len);
    if ((header_size < sizeof(xip_hdr_t)) || ((total_size < header_size) || (packet->size < total_size))) {
        return;
    }

    // 校验和要求检查
    pre_checksum = iphdr->hdr_checksum;
    iphdr->hdr_checksum = 0;
    if (pre_checksum != checksum16((uint16_t*)iphdr, header_size, 0, 1)) {
        return;
    }
    iphdr->hdr_checksum = pre_checksum;

    // 只处理目标IP为自己的数据包，其它广播之类的IP全部丢掉
    if (!xipaddr_is_equal_buf(&netif_ipaddr, iphdr->dest_ip)) {
        return;
    }

    xipaddr_from_buf(&src_ip, iphdr->src_ip);
    switch(iphdr->protocol) {
        case XNET_PROTOCOL_UDP:
            if (packet->size >= sizeof(xudp_hdr_t)) {
                xudp_hdr_t *udp_hdr = (xudp_hdr_t *) (packet->data + header_size);
                xudp_t *udp = xudp_find(swap_order16(udp_hdr->dest_port));
                if (udp) {
                    truncate_packet(packet, total_size);
                    remove_header(packet, header_size);
                    xudp_in(udp, &src_ip, packet);
                } else {
                    xicmp_dest_unreach(XICMP_CODE_PORT_UNREACH, iphdr);
                }
            }
            break;
        case XNET_PROTOCOL_TCP:
            truncate_packet(packet, total_size);
            remove_header(packet, header_size);
            xtcp_in(&src_ip, packet);
            break;
        case XNET_PROTOCOL_ICMP:
            remove_header(packet, header_size);
            xicmp_in(&src_ip, packet);
            break;
        default:
            // 这里应当写成协议不可达，因为没有任何协议能处理输入数据包
            xicmp_dest_unreach(XICMP_CODE_PRO_UNREACH, iphdr);
            break;
    }
}

/**
 * IP包的输出
 * @param protocol 上层协议，ICMP、UDP或TCP
 * @param dest_ip
 * @param packet
 * @return
 */
xnet_err_t xip_out(xnet_protocol_t protocol, xipaddr_t* dest_ip, xnet_packet_t * packet) {
    static uint32_t ip_packet_id = 0;
    xip_hdr_t * iphdr;

    add_header(packet, sizeof(xip_hdr_t));
    iphdr = (xip_hdr_t*)packet->data;
    iphdr->version = XNET_VERSION_IPV4;
    iphdr->hdr_len = sizeof(xip_hdr_t) / 4;
    iphdr->tos = 0;
    iphdr->total_len = swap_order16(packet->size);
    iphdr->id = swap_order16(ip_packet_id);
    iphdr->flags_fragment = 0;
    iphdr->ttl = XNET_IP_DEFAULT_TTL;
    iphdr->protocol = protocol;
    memcpy(iphdr->dest_ip, dest_ip->array, XNET_IPV4_ADDR_SIZE);
    memcpy(iphdr->src_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    iphdr->hdr_checksum = 0;
    iphdr->hdr_checksum = checksum16((uint16_t *)iphdr, sizeof(xip_hdr_t), 0, 1);;

    ip_packet_id++;
    return ethernet_out(dest_ip, packet);
}

/**
 * icmp初始化
 */
void xicmp_init(void) {}

/**
 * 发送ICMP ECHO响应，即回应ping
 * @param icmp_hdr 收到的icmp包头
 * @param src_ip 包的来源ip
 * @param packet 收到的数据包
 * @return 处理结果
 */
static xnet_err_t reply_icmp_request(xicmp_hdr_t * icmp_hdr, xipaddr_t* src_ip, xnet_packet_t * packet) {
    xicmp_hdr_t * replay_hdr;
    xnet_packet_t * tx = xnet_alloc_for_send(packet->size);

    replay_hdr = (xicmp_hdr_t *)packet->data;
    replay_hdr->type = XICMP_CODE_ECHO_REPLY;
    replay_hdr->code = 0;
    replay_hdr->id = icmp_hdr->id;
    replay_hdr->seq = icmp_hdr->seq;
    replay_hdr->checksum = 0;
    memcpy(((uint8_t *)replay_hdr) + sizeof(xicmp_hdr_t), ((uint8_t *)icmp_hdr) + sizeof(xicmp_hdr_t),
            packet->size - sizeof(xicmp_hdr_t));
    replay_hdr->checksum = checksum16((uint16_t*)replay_hdr, tx->size, 0, 1);
    return xip_out(XNET_PROTOCOL_ICMP, src_ip, packet);
}

/**
 * ICMP包输入处理
 * @param src_ip 数据包来源
 * @param packet 待处理的数据包
 */
void xicmp_in(xipaddr_t *src_ip, xnet_packet_t * packet) {
    xicmp_hdr_t* icmphdr = (xicmp_hdr_t *)packet->data;

    if ((packet->size >= sizeof(xicmp_hdr_t)) && (icmphdr->type == XICMP_CODE_ECHO_REQUEST)) {
        reply_icmp_request(icmphdr, src_ip, packet);
    }
}

/**
 * 发送ICMP端口不可达或协议不可达的响应
 * @param code 不可达的类型码
 * @param ip_hdr 收到的ip包
 * @return 处理结果
 */
xnet_err_t xicmp_dest_unreach(uint8_t code, xip_hdr_t *ip_hdr) {
    xicmp_hdr_t * icmp_hdr;
    xipaddr_t dest_ip;
    xnet_packet_t* packet;

    // 计算要拷贝的ip数据量
    uint16_t ip_hdr_size = ip_hdr->hdr_len * 4;
    uint16_t ip_data_size = swap_order16(ip_hdr->total_len) - ip_hdr_size;

    // RFC文档里写的是8字节。但实际测试windows上发现复制了不止8个字节
    ip_data_size = ip_hdr_size + min(ip_data_size, 8);

    // 生成数据包，然后发送
    packet = xnet_alloc_for_send(ip_data_size + sizeof(xicmp_hdr_t));
    icmp_hdr = (xicmp_hdr_t*)packet->data;
    icmp_hdr->type = XICMP_TYPE_UNREACH;
    icmp_hdr->code = code;
    icmp_hdr->checksum = 0;
    icmp_hdr->id = icmp_hdr->seq = 0;
    memcpy(((uint8_t *)icmp_hdr) + sizeof(xicmp_hdr_t), ip_hdr, ip_data_size);
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = checksum16((uint16_t *)icmp_hdr, packet->size, 0, 1);
    xipaddr_from_buf(&dest_ip, ip_hdr->src_ip);
    return xip_out(XNET_PROTOCOL_ICMP, &dest_ip, packet);
}

/**
 * 计算UDP伪校验和
 * @param src_ip 源IP
 * @param dest_ip 目标IP
 * @param protocol 协议
 * @param buf 数据区
 * @param len 数据长度
 * @return 校验和结果
 */
static uint16_t checksum_peso(const xipaddr_t *src_ip, const xipaddr_t *dest_ip,
                              uint8_t protocol, uint16_t *buf, uint16_t len) {
    uint8_t zero_protocol[2] = {0, protocol};
    uint16_t c_len = swap_order16(len);

    uint32_t sum = checksum16((uint16_t *)src_ip->array, XNET_IPV4_ADDR_SIZE, 0, 0);
    sum = checksum16((uint16_t *)dest_ip->array, XNET_IPV4_ADDR_SIZE, sum, 0);
    sum = checksum16((uint16_t *)zero_protocol, 2, sum, 0);
    sum = checksum16((uint16_t *)&c_len, 2, sum, 0);
    return checksum16(buf, len, sum, 1);
}

/**
 * UDP初始化
 */
void xudp_init(void) {
    memset(udp_socket, 0, sizeof(udp_socket));      // Free也是0，所以没什么问题
}

/**
 * UDP输入处理
 * @param udp 待处理的UDP
 * @param src_ip 数据包来源
 * @param packet 数据包结构
 */
void xudp_in(xudp_t *udp, xipaddr_t *src_ip,xnet_packet_t * packet) {
    xudp_hdr_t * udp_hdr = (xudp_hdr_t *)packet->data;
    uint16_t pre_checksum;
    uint16_t src_port;

    if ((packet->size < sizeof(xudp_hdr_t)) || (packet->size < swap_order16(udp_hdr->total_len))) {
        return;
    }

    pre_checksum = udp_hdr->checksum;
    udp_hdr->checksum = 0;
    if (pre_checksum != 0) {
        uint16_t checksum = checksum_peso(src_ip, &netif_ipaddr, XNET_PROTOCOL_UDP,
                                          (uint16_t *) udp_hdr, swap_order16(udp_hdr->total_len));
        checksum = (checksum == 0) ? 0xFFFF : checksum;
        if (checksum != pre_checksum) {
            return;
        }
    }

    src_port = swap_order16(udp_hdr->src_port);
    remove_header(packet, sizeof(xudp_hdr_t));
    if (udp->handler) {
        udp->handler(udp, src_ip, src_port, packet);
    }
}

/**
 * 发送一个UDP数据包
 * @param udp udp结构
 * @param dest_ip 目标ip
 * @param dest_port 目标端口
 * @param packet 待发送的包
 * @return 发送结果
 */
int xudp_out(xudp_t* udp, xipaddr_t * dest_ip, uint16_t dest_port, xnet_packet_t * packet) {
    xudp_hdr_t* udp_hdr;
    uint16_t checksum;

    add_header(packet, sizeof(xudp_hdr_t));
    udp_hdr = (xudp_hdr_t*)packet->data;
    udp_hdr->src_port = swap_order16(udp->local_port);
    udp_hdr->dest_port = swap_order16(dest_port);
    udp_hdr->total_len = swap_order16(packet->size);
    udp_hdr->checksum = 0;
    checksum = checksum_peso(&netif_ipaddr, dest_ip, XNET_PROTOCOL_UDP, (uint16_t *) udp_hdr, packet->size);
    udp_hdr->checksum = (checksum == 0) ? 0xFFFF : checksum;
    return xip_out(XNET_PROTOCOL_UDP, dest_ip, packet);;
}

/**
 * 打开UDP结构
 * @param handler 事件处理回调函数
 * @return 打开的xudp_t结构
 */
xudp_t* xudp_open(xudp_handler_t handler) {
    xudp_t * udp, * end;

    for (udp = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP]; udp < end; udp++) {
        if (udp->state == XUDP_STATE_FREE) {
            udp->state = XUDP_STATE_USED;
            udp->local_port = 0;
            udp->handler = handler;
            return udp;
        }
    }
    return (xudp_t *)0;
}

/**
 * 关闭UDP连接
 * @param udp 待关闭的xudp_t结构
 */
void xudp_close(xudp_t *udp) {
    udp->state = XUDP_STATE_FREE;
}

/**
 * 查找指定端口对应的udp结构
 * @param port 待查找的端口
 * @return 找到的xudp_t结构
 */
xudp_t* xudp_find(uint16_t port) {
    xudp_t * udp, * end = &udp_socket[XUDP_CFG_MAX_UDP];

    for (udp = udp_socket; udp < end; udp++) {
        if ((udp->state != XUDP_STATE_FREE) && (udp->local_port == port)) {
            return udp;
        }
    }

    return (xudp_t *)0;
}

/**
 * 绑定xudp_t结构到指定端口
 * @param udp 待绑定的结构
 * @param local_port 目标端口
 * @return 绑定结果
 */
xnet_err_t xudp_bind(xudp_t *udp, uint16_t local_port) {
    xudp_t * curr, * end;

    if (local_port == 0) {
        return XNET_ERR_PARAM;
    }

    for (curr = udp_socket, end = &udp_socket[XUDP_CFG_MAX_UDP]; curr < end; curr++) {
        if ((curr != udp) && (curr->local_port == local_port)) {
            return XNET_ERR_BINDED;
        }
    }

    udp->local_port = local_port;
    return XNET_ERR_OK;
}

/**
 * 分配一个tcp连接块
 * @return 分配结果，0-分配失败
 */
static void tcp_buf_init(xtcp_buf_t *tcp_buf) {
    // 全部指向0，无数据或未发送的数据
    tcp_buf->tail = tcp_buf->next = tcp_buf->front = 0;
    tcp_buf->data_count = tcp_buf->unacked_count = 0;
}

/**
 * 获取buf中空闲的字节量
 * @param tcp_buf 待查询的结构
 * @return 空闲的字节量
 */
static uint16_t tcp_buf_free_count(xtcp_buf_t *tcp_buf) {
    return XTCP_CFG_RTX_BUF_SIZE - tcp_buf->data_count;
}

static uint16_t tcp_buf_wait_send_count(xtcp_buf_t * tcp_buf) {
    return tcp_buf->data_count - tcp_buf->unacked_count;
}
/**
 * 增加buf中确认的数据量
 * @param tcp_buf buf缓存
 * @param size 新增确认的数据量
 */
static void tcp_buf_add_acked_count(xtcp_buf_t *tcp_buf, uint16_t size) {
    // 新增确认，需要窗口左侧移动
    tcp_buf->tail += size;
    if (tcp_buf->tail >= XTCP_CFG_RTX_BUF_SIZE) {
        tcp_buf->tail = 0;
    }
    tcp_buf->data_count -= size;
    tcp_buf->unacked_count -= size;
}

/**
 * 增加buf中未确认的数据量
 * @param tcp_buf buf缓存
 * @param size 新增未确认的数据量
 */
static void tcp_buf_add_unacked_count(xtcp_buf_t *tcp_buf, uint16_t size) {
    // 未确认增加，仅增加计数
    tcp_buf->unacked_count += size;
}

/**
 * 向buf中写入新的需要发送的数据。仅供发送使用
 * @param tcp_buf 写入buf
 * @param from 数据源
 * @param size 数据字节量
 * @return 实际写入的量，由于缓存空间有限，实际写入的可能比期望的要小一些
 */
static uint16_t tcp_buf_write(xtcp_buf_t *tcp_buf, uint8_t *from, uint16_t size) {
    int i;

    size = min(size, tcp_buf_free_count(tcp_buf));

    // 逐个拷贝，注意回绕
    for (i = 0; i < size; i++) {
        tcp_buf->data[tcp_buf->front++] = *from++;
        if (tcp_buf->front >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->front = 0;
        }
    }

    tcp_buf->data_count += size;
    return size;
}

/**
 * 从buf中读取数据用于发送
 * @param tcp_buf 读取的buf
 * @param to 读取的目的地
 * @param size 读取的字节量
 * @return 实际读取的字节量
 */
static uint16_t tcp_buf_read_for_send(xtcp_buf_t *tcp_buf, uint8_t *to, uint16_t size) {
    int i;
    uint16_t wait_send_count = tcp_buf->data_count - tcp_buf->unacked_count;

    size = min(size, wait_send_count);
    for (i = 0; i < size; i++) {
        *to++ = tcp_buf->data[tcp_buf->next++];
        if (tcp_buf->next >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->next = 0;
        }
    }

    return size;
}

/**
 * 分配一个tcp连接块
 * @return 分配结果，0-分配失败
 */
static xtcp_t * tcp_alloc(void) {
    xtcp_t * tcp, * end;

    for (tcp = tcp_socket, end = tcp_socket + XTCP_CFG_MAX_TCP; tcp < end; tcp++) {
        if (tcp->state == XTCP_STATE_FREE) {
            tcp->state = XTCP_STATE_CLOSED;
            tcp->local_port = 0;
            tcp->remote_port = 0;
            tcp->remote_ip.addr = 0;
            tcp->handler = (xtcp_handler_t)0;
            tcp->remote_win = XTCP_MSS_DEFAULT;
            tcp->remote_mss = XTCP_MSS_DEFAULT;
            tcp->unack_seq = tcp->next_seq = tcp_get_init_seq();
            tcp->ack = 0;
            return tcp;
        }
    }

    return (xtcp_t *)0;
}

/**
 * 释放一个连接块
 * @param tcp 待释放的
 */
static void tcp_free(xtcp_t* tcp) {
    tcp->state = XTCP_STATE_FREE;
}

/**
 * 根据远端的端口、ip找一个对应的tcp连接进行处理。
 * 优先找端口、IP全匹配的，其次找处于监听状态的
 * @param remote_ip
 * @param remote_port
 * @param local_port
 * @return
 */
static xtcp_t* tcp_find(xipaddr_t *remote_ip, uint16_t remote_port, uint16_t local_port) {
    xtcp_t * tcp, * end;
    xtcp_t * founded_tcp = (xtcp_t *)0;

    for (tcp = tcp_socket, end = tcp_socket + XTCP_CFG_MAX_TCP; tcp < end; tcp++) {
        if ((tcp->state == XTCP_STATE_FREE) || (tcp->local_port != local_port)) {
            continue;
        }

        if (xipaddr_is_equal(remote_ip, &tcp->remote_ip) && (remote_port == tcp->remote_port)) {
            return tcp;     // 优先，远程的端口和ip完全相同，立即返回
        }

        if (tcp->state == XTCP_STATE_LISTEN) {
            founded_tcp = tcp;  // 没有，默认使用监听端口
        }
    }

    return founded_tcp;
}

/**
 * 发送TCP复位包
 */
static xnet_err_t tcp_send_reset (uint32_t sender_seq, uint16_t local_port, xipaddr_t * remote_ip, uint16_t remote_port) {
    xnet_packet_t * packet = xnet_alloc_for_send(sizeof(xtcp_hdr_t));
    xtcp_hdr_t * tcp_hdr = (xtcp_hdr_t *)packet->data;

    tcp_hdr->src_port = swap_order16(local_port);
    tcp_hdr->dest_port = swap_order16(remote_port);
    tcp_hdr->seq = 0;                               // 固定为0即可
    ++sender_seq;       // 注意，不要放在swap_order32，会导致++多次
    tcp_hdr->ack = swap_order32(sender_seq);          // 响应指定的发送ack，即对上次发送的包的回应
    tcp_hdr->hdr_flags.all = 0;
    tcp_hdr->hdr_flags.field.hdr_len = sizeof(xtcp_hdr_t) / 4;
    tcp_hdr->hdr_flags.field.flags = XTCP_FLAG_RST | XTCP_FLAG_ACK;
    tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);
    tcp_hdr->window = 0;
    tcp_hdr->urgent_ptr = 0;
    tcp_hdr->checksum = 0;
    tcp_hdr->checksum = checksum_peso(&netif_ipaddr, remote_ip, XNET_PROTOCOL_TCP, (uint16_t *) packet->data, packet->size);
    tcp_hdr->checksum = tcp_hdr->checksum ? tcp_hdr->checksum : 0xFFFF;
    return xip_out(XNET_PROTOCOL_TCP, remote_ip, packet);
}

/**
 * 将发送缓冲区中的数据发送出去。尽最大努力发送最多
 * @param tcp 处理的tcp连接
 * @param flags 发送的标志位
 * @return 发送结果
 */
static xnet_err_t tcp_send(xtcp_t *tcp, uint8_t flags) {
    xnet_packet_t * packet;
    xtcp_hdr_t * tcp_hdr;
    xnet_err_t err;
    uint16_t data_size = tcp_buf_wait_send_count(&tcp->tx_buf);
    uint16_t opt_size = (flags & XTCP_FLAG_SYN) ? 4 : 0;     // mss长度

    // 判断当前允许发送的字节量
    if (tcp->remote_win) {
        data_size = min(data_size, tcp->remote_win);
        data_size = min(data_size, tcp->remote_mss);
        if (data_size + opt_size > XTCP_DATA_MAX_SIZE) {
            data_size = XTCP_DATA_MAX_SIZE - opt_size;
        }
    } else {
        data_size = 0;      // 窗口为0，不允许发数据，但允许FIN+SYN等
    }

    packet = xnet_alloc_for_send(data_size + opt_size + sizeof(xtcp_hdr_t));
    tcp_hdr = (xtcp_hdr_t *)packet->data;
    tcp_hdr->src_port = swap_order16(tcp->local_port);
    tcp_hdr->dest_port = swap_order16(tcp->remote_port);
    tcp_hdr->seq = swap_order32(tcp->next_seq);
    tcp_hdr->ack = swap_order32(tcp->ack);
    tcp_hdr->hdr_flags.all = 0;
    tcp_hdr->hdr_flags.field.hdr_len = (opt_size + sizeof(xtcp_hdr_t)) / 4;
    tcp_hdr->hdr_flags.field.flags = flags;
    tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);
    tcp_hdr->window = swap_order16(tcp_buf_free_count(&tcp->rx_buf));
    tcp_hdr->checksum = 0;
    tcp_hdr->urgent_ptr = 0;
    if (flags & XTCP_FLAG_SYN) {
        uint8_t * opt_data = packet->data + sizeof(xtcp_hdr_t);
        opt_data[0] = XTCP_KIND_MSS;
        opt_data[1] = 4;        // 该选项总长，含0,1字节
        *(uint16_t *)(opt_data + 2) = swap_order16(XTCP_MSS_DEFAULT);
    }

    tcp_buf_read_for_send(&tcp->tx_buf, packet->data + opt_size + sizeof(xtcp_hdr_t), data_size);
    tcp_hdr->checksum = checksum_peso(&netif_ipaddr, &tcp->remote_ip, XNET_PROTOCOL_TCP, (uint16_t *) packet->data, packet->size);
    tcp_hdr->checksum = tcp_hdr->checksum ? tcp_hdr->checksum : 0xFFFF;
    err = xip_out(XNET_PROTOCOL_TCP, &tcp->remote_ip, packet);
    if (err < 0) return err;

    tcp->remote_win -= data_size;               // 同时远端可用窗口减少
    tcp->next_seq += data_size;                 // 新发送，序号要增加
    tcp_buf_add_unacked_count(&tcp->tx_buf, data_size); // 增加已发送但未确认的量
    if (flags & (XTCP_FLAG_SYN | XTCP_FLAG_FIN)) {        // FIN占用1个序号
        tcp->next_seq++;
    }
    return XNET_ERR_OK;
}

/**
 * 从tcp包头中读取选项字节。简单起见，仅读取mss字段
 * @param tcp 待读取的tcp连接
 * @param tcp_hdr tcp包头
 */
static void tcp_read_mss(xtcp_t *tcp, xtcp_hdr_t *tcp_hdr) {
    uint16_t opt_len = tcp_hdr->hdr_flags.field.hdr_len * 4 - sizeof(xtcp_hdr_t);

    if (opt_len == 0) {
        tcp->remote_mss = XTCP_MSS_DEFAULT;
    } else {
        uint8_t * opt_data = (uint8_t *)tcp_hdr + sizeof(xtcp_hdr_t);
        uint8_t * opt_end = opt_data + opt_len;

        while ((*opt_data != XTCP_KIND_END) && (opt_data < opt_end)) {
            if ((*opt_data++ == XTCP_KIND_MSS) && (*opt_data++ == 4)) {
                tcp->remote_mss = swap_order16(*(uint16_t *) opt_data);
                opt_data += 2;
            }
        }
    }
}

/**
 * 处理tcp连接请求
 */
static void tcp_process_accept(xtcp_t *listen_tcp, xipaddr_t *remote_ip, xtcp_hdr_t *tcp_hdr) {
    uint16_t hdr_flags = swap_order16(tcp_hdr->hdr_flags.all);

    // 对于监听套接字，仅处理syn，其余发reset处理
    if (hdr_flags & XTCP_FLAG_SYN) {
        xnet_err_t err;
        uint32_t ack = swap_order32(tcp_hdr->seq) + 1;

        xtcp_t* new_tcp = tcp_alloc();
        if (!new_tcp) return;

        new_tcp->state = XTCP_STATE_SYNC_RECVD;
        new_tcp->local_port = listen_tcp->local_port;
        new_tcp->handler = listen_tcp->handler;
        new_tcp->remote_port = swap_order16(tcp_hdr->src_port);    // 肯定会成功的，因为这里端口太多
        new_tcp->remote_ip.addr = remote_ip->addr;
        new_tcp->ack = ack;                                     // 对方的seq + syn的长度1，不算选项
        new_tcp->next_seq = new_tcp->unack_seq = tcp_get_init_seq();     // 使用自己的，不用监听套接字的
        new_tcp->remote_win = swap_order16(tcp_hdr->window);
        tcp_read_mss(new_tcp, tcp_hdr);         // 读选项，主要是mss

        err = tcp_send(new_tcp, XTCP_FLAG_SYN | XTCP_FLAG_ACK);
        if (err < 0) {
            tcp_free(new_tcp);
            return;
        }

        return;
    }

    tcp_send_reset(swap_order16(tcp_hdr->seq), listen_tcp->local_port, remote_ip, swap_order16(tcp_hdr->src_port));
}

/**
 * 处理tcp复位包的输入
 */
static void tcp_process_reset(xtcp_t * tcp, xtcp_hdr_t * tcp_hdr) {
    // 仅当收到的复位与与自己期望的一致，因为可能有很早前发的复位包这里才到达，此时不应处理
    if (tcp->ack == swap_order32(tcp_hdr->seq)) {
        tcp->handler(tcp, XTCP_CONN_CLOSED);
        tcp_free(tcp);
    }
}

/**
 * TCP包的输入处理
 */
void xtcp_in(xipaddr_t *remote_ip, xnet_packet_t * packet) {
    xtcp_hdr_t * tcp_hdr = (xtcp_hdr_t *)packet->data;
    uint16_t hdr_flags, hdr_size;
    xtcp_t* tcp;
    uint16_t src_port, dest_port;
    uint32_t remote_ack, remote_seq;

    // 大小检查，至少要有负载数据
    if (packet->size < sizeof(xtcp_hdr_t)) {
        return;
    }

    // 从包头中解析相关参数
    src_port = swap_order16(tcp_hdr->src_port);
    dest_port = swap_order16(tcp_hdr->dest_port);
    hdr_flags = swap_order16(tcp_hdr->hdr_flags.all);
    hdr_size = (hdr_flags >> 12) * 4;
    remote_seq = swap_order32(tcp_hdr->seq);
    remote_ack = swap_order32(tcp_hdr->ack);

    // 找到对应处理的tcb，可能是监听tcb，也可能是已经连接的tcb，没有处理项，则复位通知
    tcp = tcp_find(remote_ip, src_port, dest_port);
    if (tcp == (xtcp_t *)0) {
        tcp_send_reset(swap_order32(tcp_hdr->seq), dest_port, remote_ip, src_port);
        return;
    }
    tcp->remote_win = swap_order16(tcp_hdr->window);

    // 监听套接字，只能接收SYNC请求，其它包直接发送复位报错。没有可用的tcb，也发送复位
    if (tcp->state == XTCP_STATE_LISTEN) {
        tcp_process_accept(tcp, remote_ip, tcp_hdr);
        return;
    }

    // 收到复位处理
    if (hdr_flags & XTCP_FLAG_RST) {
        tcp_process_reset(tcp, tcp_hdr);
        return;
    }

    // 序号不一致，可能要进行重发
    if (remote_seq != tcp->ack) {
        if (tcp->state != XTCP_STATE_ESTABLISHED) {
            // 非连接状态下，直接复位，关闭简单处理
            tcp->state = XTCP_STATE_ESTABLISHED;
            tcp->handler(tcp, XTCP_CONN_CLOSED);
            tcp_send_reset(swap_order16(remote_seq), tcp->local_port, remote_ip, swap_order16(src_port));
            tcp_free(tcp);
        } else {
            // 数据重发,
        }

        return;
    }

    // 序号相同时的处理
    remove_header(packet, hdr_size);
    switch (tcp->state) {
        case XTCP_STATE_SYNC_RECVD: {
            // 已经收到SYN，且发了SYN+ACK，检查是否是ACK，是，则连接成功
            if (hdr_flags & XTCP_FLAG_ACK) {
                // 收到ack，则说明已经建立成功，进入已经连接成功状态
                tcp->unack_seq++;       // syn占用了一个序号
                tcp->state = XTCP_STATE_ESTABLISHED;
                tcp->handler(tcp, XTCP_CONN_CONNECTED);
            }
            break;
        }
        case XTCP_STATE_ESTABLISHED:
            // 这里可能收到数据，或者FIN
            if (hdr_flags & (XTCP_FLAG_ACK | XTCP_FLAG_FIN)) {
                uint16_t read_size ;

                // 先处理ACK的值，即ack确认之前发的数据被接收了，有2种情况
                // 1.远程ack的值比自己未确认的值相等或更大，则说明有部分数据被远端接收确认了
                // 2.远程ack < tcp_unack_seq，即可能之前重发的ack，不处理
                // 简单起见，不考虑序号溢出问题
                if (hdr_flags & XTCP_FLAG_ACK) {
                    if ((tcp->unack_seq < remote_ack) && (remote_ack <= tcp->next_seq)) {
                        uint16_t curr_ack_size = remote_ack - tcp->unack_seq;
                        tcp_buf_add_acked_count(&tcp->tx_buf, curr_ack_size);
                        tcp->unack_seq += curr_ack_size;
                    }
                }

                // 再读取当前包中的数据，里面可能是携带有数据的，即便是FIN，也可能是带有数据
                read_size = tcp_recv(tcp, (uint8_t)hdr_flags, packet->data, packet->size);

                // 再然后，根据当前的标志位处理
                if (hdr_flags & XTCP_FLAG_FIN) {
                    // 收到关闭请求，发送ACK，同时也发送FIN，同时直接主动关掉，省得麻烦
                    // 这样就不必进入CLOSE_WAIT，然后再等待对方的ACK
                    tcp->state = XTCP_STATE_LAST_ACK;
                    tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
                } else if (read_size) {
                    // 非FIN，看看有无数据，有的话发ACK响应
                    // 如果是是收到数据，发ACK响应。
                    tcp_send(tcp, XTCP_FLAG_ACK);
                    tcp->handler(tcp, XTCP_CONN_DATA_RECV);
                } else if (tcp_buf_wait_send_count(&tcp->tx_buf)) {
                    // 或者看看有没有数据要发，有的话，同时发数据即ack
                    // 没有收到数据，可能是对方发来的ACK。此时，有数据有就发数据，没数据就不理会
                    tcp_send(tcp, XTCP_FLAG_ACK);
                }
                // 其它情况，即对方只是简单的一个ack,不发送任何响应处理
            }
            break;
        case XTCP_STATE_FIN_WAIT_1:     // 收到ack后，自己的发送已经关掉，但仍可接收，等待对方发FIN
            if (hdr_flags & XTCP_FLAG_ACK) {
                tcp->state = XTCP_STATE_FIN_WAIT_2;    // 对方也许不想暂时关闭
            } else if (hdr_flags & XTCP_FLAG_FIN) {
                tcp->state = XTCP_STATE_CLOSING;        // 对方同时关闭发送，关掉整个
                tcp_send(tcp, XTCP_FLAG_ACK);
            }
            break;
        case XTCP_STATE_FIN_WAIT_2:    // 自己发送关闭，但仍然能数据接收
            if (hdr_flags & (XTCP_FLAG_FIN | XTCP_FLAG_ACK)) {
                uint16_t read_size;

                if (hdr_flags & XTCP_FLAG_ACK) {    // 先处理之前发送的确认, todo: 设置
                    if ((tcp->unack_seq <= remote_ack) && (remote_ack <= tcp->next_seq)) {
                        uint16_t curr_ack_size = remote_ack - tcp->unack_seq;
                        tcp_buf_add_acked_count(&tcp->tx_buf, curr_ack_size);
                        tcp->unack_seq += curr_ack_size;
                    }
                }

                read_size = tcp_recv(tcp, (uint8_t) hdr_flags, packet->data, packet->size);

                if (hdr_flags & XTCP_FLAG_FIN) {          // FIN
                    tcp_send(tcp, XTCP_FLAG_ACK);        // 对方也关闭
                    tcp->state = XTCP_STATE_CLOSED;
                    tcp_free(tcp);                      // 直接释放掉，不进入TIMED_WAIT
                } else if (read_size) {                  // 仅接收，发ack响应
                    tcp_send(tcp, XTCP_FLAG_ACK);
                    tcp->handler(tcp, XTCP_CONN_DATA_RECV);
                }
            }
            break;
        case XTCP_STATE_CLOSING:
            if (hdr_flags & XTCP_FLAG_ACK) {
                tcp->handler(tcp, XTCP_CONN_CLOSED);
                tcp_free(tcp);              // 直接释放掉，不进入TIMED_WAIT
            }
            break;
        case XTCP_STATE_LAST_ACK:
            if (hdr_flags & XTCP_FLAG_ACK) {
                tcp->handler(tcp, XTCP_CONN_CLOSED);
                tcp_free(tcp);
            }
            break;
        default:
            break;
    }
}

/**
 * TCP初始化
 */
void xtcp_init(void) {
    memset(tcp_socket, 0, sizeof(tcp_socket));
}

/**
 * 打开TCP
 */
xtcp_t * xtcp_open(xtcp_handler_t handler) {
    xtcp_t * tcp = tcp_alloc();
    if (!tcp) return (xtcp_t *)0;

    tcp->state = XTCP_STATE_CLOSED;
    tcp->handler = handler;
    return tcp;
}

/**
 * 建立tcp与指定本地端口的关联，使得其能够处理来自该端口的包
 * 以及通过该端口发送数据包
 */
xnet_err_t xtcp_bind(xtcp_t* tcp, uint16_t local_port) {
    if (local_port == 0) {
        return XNET_ERR_PARAM;
    }

    xtcp_t * curr, * end;
    for (curr = tcp_socket, end = &tcp_socket[XUDP_CFG_MAX_UDP]; curr < end; curr++) {
        if ((curr != tcp) && (curr->local_port == local_port)) {
            return XNET_ERR_BINDED;
        }
    }

    tcp->local_port = local_port;
    return XNET_ERR_OK;
}

/**
 * 控制tcp进入监听状态
 */
xnet_err_t xtcp_listen(xtcp_t * tcp) {
    if (tcp->state == XTCP_STATE_CLOSED) {
        tcp->state = XTCP_STATE_LISTEN;
        return XNET_ERR_OK;
    }

    return XNET_ERR_STATE;
}

/**
 * 向tcp发送数据
 */
int xtcp_write(xtcp_t * tcp, uint8_t * data, uint16_t size) {
    uint16_t send_size;

    if ((tcp->state != XTCP_STATE_ESTABLISHED) && (tcp->state != XTCP_STATE_CLOSE_WAIT)) {
        return -1;
    }

    send_size = tcp_buf_write(&tcp->tx_buf, data, size);
    if (send_size) {
        // 考虑到远程窗口可能为0，所以下面的调用不一定发送数据
        // 数据将仅仅停留在缓存中，当下次收到对方的win更新时，再进行发送
        tcp_send(tcp, XTCP_FLAG_ACK);       // 不检查返回值，数据已经在缓冲区中
     }
    return send_size;
}

/**
 * 关掉tcp连接
 */
xnet_err_t xtcp_close(xtcp_t *tcp) {
    xnet_err_t err;

    if ((tcp->state == XTCP_STATE_ESTABLISHED) | (tcp->state == XTCP_STATE_SYNC_RECVD)) {
        err = tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
        if (err < 0) return err;
        tcp->state = XTCP_STATE_FIN_WAIT_1;
    } else {
        tcp_free(tcp);
    }
    return XNET_ERR_OK;
}

/**
 * 协议栈的初始化
 */
void xnet_init (void) {
    ethernet_init();
    xarp_init();
    xip_init();
    xicmp_init();
    xudp_init();
    xtcp_init();
    srand(xsys_get_time());
}

/**
 * 轮询处理数据包，并在协议栈中处理
 */
void xnet_poll(void) {
    ethernet_poll();
    xarp_poll();
}
