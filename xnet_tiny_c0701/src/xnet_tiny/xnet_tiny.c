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
#include "xnet_tiny.h"

#define ms_to_tmo(ms)           (ms / XARP_TIMER_PERIOD)
#define min(a, b)               ((a) > (b) ? (b) : (a))
#define XTCP_HDR_MAX_SIZE       (XNET_CFG_PACKET_MAX_SIZE - sizeof(xether_hdr_t) - sizeof(xip_hdr_t) - sizeof(xtcp_hdr_t))
#define tcp_get_init_seq()      ((rand() << 16) + rand())

static const xipaddr_t netif_ipaddr = XNET_CFG_NETIF_IP;
static const uint8_t ether_broadcast[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t netif_mac[XNET_MAC_ADDR_SIZE];                   // mac地址
static xnet_packet_t tx_packet, rx_packet;                      // 接收与发送缓冲区
static xarp_entry_t arp_entry;                                  // 节省内存，只使用一个ARP表项
static xnet_time_t arp_timer;                                   // ARP扫描定时
static xnet_time_t tcp_timer;                                   // TCP扫描定时
static xudp_t udp_socket[XUDP_CFG_MAX_UDP];                     // UDP连接块
static xtcp_t tcp_socket[XTCP_CFG_MAX_TCP];                     // TCP连接块

static void update_arp_entry(uint8_t* src_ip, uint8_t* mac_addr);

#define swap_order16(v)   ((((v) & 0xFF) << 8) | (((v) >> 8) & 0xFF))
#define swap_order32(v)   ((((v >> 0) & 0xFF) << 24) | (((v >> 8) & 0xFF) << 16) | (((v >> 16) & 0xFF) << 8) | ((v >> 24) & 0xFF))
#define xipaddr_is_equal(addr1, addr2)       ((addr1)->addr == (addr2)->addr)
#define xipaddr_is_equal_buf(addr, buf)      (memcmp((addr)->array, (buf), XNET_IPV4_ADDR_SIZE) == 0)
#define xipaddr_from_buf(dest, buf)          ((dest)->addr = *(uint32_t *)(buf))

int xnet_check_tmo(xnet_time_t * time, uint32_t ms) {
    xnet_time_t curr = xsys_get_time(), pre_time = *time;
    *time = curr;
    return (ms == 0) ? 0 : ((curr - pre_time) > ms / 100);
}

xnet_packet_t * xnet_alloc_for_send(uint16_t data_size) {
    tx_packet.data = tx_packet.payload + XNET_CFG_PACKET_MAX_SIZE - data_size;
    tx_packet.size = data_size;
    return &tx_packet;
}

xnet_packet_t * xnet_alloc_for_read(uint16_t data_size) {
    rx_packet.data = rx_packet.payload;
    return &rx_packet;
}

static void add_header_for_send(xnet_packet_t * packet, uint16_t header_size) {
    packet->data -= header_size;
    packet->size += header_size;
}

static void remove_header_for_read(xnet_packet_t * packet, uint16_t header_size) {
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

static xnet_err_t ethernet_init (void) {
    xnet_err_t err = xnet_driver_open(netif_mac);
    if (err < 0) return err;

    return xarp_make_request(&netif_ipaddr);
}

static xnet_err_t ethernet_out_to(xnet_protocol_t protocol, const uint8_t *mac_addr, xnet_packet_t * packet) {
    xether_hdr_t* ether_hdr;

    add_header_for_send(packet, sizeof(xether_hdr_t));
    ether_hdr = (xether_hdr_t*)packet->data;
    memcpy(ether_hdr->dest, mac_addr, XNET_MAC_ADDR_SIZE);
    memcpy(ether_hdr->src, netif_mac, XNET_MAC_ADDR_SIZE);
    ether_hdr->protocol = swap_order16(protocol);
    return xnet_driver_send(packet);
}

static xnet_err_t ethernet_out (xipaddr_t * dest_ip, xnet_packet_t * packet) {
    xnet_err_t err;
    uint8_t * mac_addr;

    if ((err = xarp_resolve(dest_ip, &mac_addr) == XNET_ERR_OK)) {
        return ethernet_out_to(XNET_PROTOCOL_IP, mac_addr, packet);
    }
    return err;
}

static void ethernet_in (xnet_packet_t * packet) {
    if (packet->size <= sizeof(xether_hdr_t)) {
        return;
    }

    xether_hdr_t* hdr = (xether_hdr_t*)packet->data;
    switch (swap_order16(hdr->protocol)) {
        case XNET_PROTOCOL_ARP:
            remove_header_for_read(packet, sizeof(xether_hdr_t));
            xarp_in(packet);
            break;
        case XNET_PROTOCOL_IP: {
            xip_hdr_t *iphdr = (xip_hdr_t *) (packet->data + sizeof(xether_hdr_t));
            if (packet->size >= sizeof(xether_hdr_t) + sizeof(xip_hdr_t)) {
                if (memcmp(iphdr->dest_ip, &netif_ipaddr.array, XNET_IPV4_ADDR_SIZE) == 0) {
                    update_arp_entry(iphdr->src_ip, hdr->src);
                }
            }

            remove_header_for_read(packet, sizeof(xether_hdr_t));
            xip_in(packet);
            break;
        }
    }
}

static void ethernet_poll (void) {
    xnet_packet_t * packet;

    if (xnet_driver_read(&packet) == XNET_ERR_OK) {
        ethernet_in(packet);
    }
}

void xarp_init(void) {
    arp_entry.state = XARP_ENTRY_FREE;
    xnet_check_tmo(&arp_timer, 0);
}

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
                        arp_entry.tmo = ms_to_tmo(XARP_CFG_ENTRY_PENDING_TMO);
                    }
                }
                break;
            case XARP_ENTRY_OK:
                if (--arp_entry.tmo == 0) {     // 超时，重新请求
                    xarp_make_request(&arp_entry.ipaddr);
                    arp_entry.state = XARP_ENTRY_RESOLVING;
                    arp_entry.tmo = ms_to_tmo(XARP_CFG_ENTRY_PENDING_TMO);
                }
                break;
        }
    }
}

int xarp_make_response(xarp_packet_t * arp_packet) {
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

int xarp_make_request(const xipaddr_t * ipaddr) {
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

int xarp_find(const xipaddr_t* ipaddr, uint8_t** mac_addr) {
    if ((arp_entry.state == XARP_ENTRY_OK) && xipaddr_is_equal(ipaddr, &arp_entry.ipaddr)) {
        *mac_addr = arp_entry.macaddr;
        return 0;
    }

    return -1;
}

xnet_err_t xarp_resolve(const xipaddr_t * ipaddr, uint8_t ** mac_addr) {
    if (xarp_find(ipaddr, mac_addr) == 0) {
        return XNET_ERR_OK;
    }

    xarp_make_request(ipaddr);
    return XNET_ERR_NONE;
}

static void update_arp_entry(uint8_t * src_ip, uint8_t * mac_addr) {
    memcpy(arp_entry.ipaddr.array, src_ip, XNET_IPV4_ADDR_SIZE);
    memcpy(arp_entry.macaddr, mac_addr, 6);
    arp_entry.state = XARP_ENTRY_OK;
    arp_entry.tmo = ms_to_tmo(XARP_CFG_ENTRY_OK_TMO);
    arp_entry.retry_cnt = XARP_CFG_MAX_RETRIES;
}

void xarp_in(xnet_packet_t * packet) {
    if (packet->size >= sizeof(xarp_packet_t)) {
        xarp_packet_t * arp_packet = (xarp_packet_t *) packet->data;
        uint16_t opcode = swap_order16(arp_packet->opcode);

        if ((swap_order16(arp_packet->hw_type) != XARP_HW_ETHER) ||
            (arp_packet->hw_len != XNET_MAC_ADDR_SIZE) ||
            (swap_order16(arp_packet->pro_type) != XNET_PROTOCOL_IP) ||
            (arp_packet->pro_len != XNET_IPV4_ADDR_SIZE)
            || ((opcode != XARP_REQUEST) && (opcode != XARP_REPLY))) {
            return;
        }

        switch (swap_order16(arp_packet->opcode)) {
            case XARP_REQUEST:  // 请求，回送响应
                xarp_make_response(arp_packet);
                break;
            case XARP_REPLY:    // 响应，更新自己的表
                update_arp_entry(arp_packet->sender_ip, arp_packet->sender_mac);
                break;
        }
    }
}

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

    while ((high = checksum >> 16) != 0) {
        checksum = high + (checksum & 0xffff);
    }
    return complement ? (uint16_t)~checksum : (uint16_t)checksum;
}

void xip_init(void) {}

void xip_in(xnet_packet_t * packet) {
    xip_hdr_t* iphdr = (xip_hdr_t*)packet->data;
    uint32_t total_size, header_size;
    uint16_t pre_checksum;
    xipaddr_t src_ip;

    if (iphdr->version != XNET_VERSION_IPV4) {
        return;
    }

    header_size = iphdr->hdr_len * 4;
    total_size = swap_order16(iphdr->total_len);
    if ((header_size < sizeof(xip_hdr_t)) || ((total_size < header_size) || (packet->size < total_size))) {
        return;
    }

    pre_checksum = iphdr->hdr_checksum;
    iphdr->hdr_checksum = 0;
    if (pre_checksum != checksum16((uint16_t*)iphdr, header_size, 0, 1)) {
        return;
    }

    iphdr->flags_fragment.all = swap_order16(iphdr->flags_fragment.all);
    if (iphdr->flags_fragment.sub.more_fragment || iphdr->flags_fragment.sub.fragment_offset) {
        return;
    }

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
                    remove_header_for_read(packet, header_size);
                    xudp_in(udp, &src_ip, packet);
                } else {
                    xicmp_dest_unreach(XICMP_CODE_PORT_UNREACH, iphdr);
                }
            }
            break;
        case XNET_PROTOCOL_TCP:
            truncate_packet(packet, total_size);
            remove_header_for_read(packet, header_size);
            xtcp_in(&src_ip, packet);
            break;
        case XNET_PROTOCOL_ICMP:
            remove_header_for_read(packet, header_size);
            xicmp_in(&src_ip, packet);
            break;
        default:
            xicmp_dest_unreach(XICMP_CODE_PRO_UNREACH, iphdr);
            break;
    }
}

xnet_err_t xip_out(uint8_t protocol, xipaddr_t* dest_ip, xnet_packet_t * packet) {
    static uint32_t ip_packet_id = 0;
    xip_hdr_t * iphdr;
    uint16_t checksum;

    if (packet->size >= 65535) {
        return XNET_ERR_MEM;
    }

    add_header_for_send(packet, sizeof(xip_hdr_t));
    iphdr = (xip_hdr_t*)packet->data;
    iphdr->version = XNET_VERSION_IPV4;
    iphdr->hdr_len = sizeof(xip_hdr_t) / 4;
    iphdr->tos = 0;
    iphdr->total_len = swap_order16(packet->size);
    iphdr->id = swap_order16(ip_packet_id);
    iphdr->flags_fragment.all = 0;
    iphdr->ttl = XNET_IP_DEFAULT_TTL;
    iphdr->protocol = protocol;
    memcpy(iphdr->dest_ip, dest_ip->array, XNET_IPV4_ADDR_SIZE);
    memcpy(iphdr->src_ip, netif_ipaddr.array, XNET_IPV4_ADDR_SIZE);
    iphdr->hdr_checksum = 0;
    checksum = checksum16((uint16_t *)iphdr, sizeof(xip_hdr_t), 0, 1);
    iphdr->hdr_checksum = checksum;

    ip_packet_id++;
    return ethernet_out(dest_ip, packet);
}

void xicmp_init(void) {}

static int reply_icmp_request(xicmp_hdr_t * icmp_hdr, xipaddr_t* src_ip, xnet_packet_t * packet) {
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

void xicmp_in(xipaddr_t *src_ip, xnet_packet_t * packet) {
    xicmp_hdr_t* icmphdr = (xicmp_hdr_t *)packet->data;

    if ((packet->size >= sizeof(xicmp_hdr_t)) && (icmphdr->type == XICMP_CODE_ECHO_REQUEST)) {
        reply_icmp_request(icmphdr, src_ip, packet);
    }
}

int xicmp_dest_unreach(uint8_t code, xip_hdr_t *ip_hdr) {
    xicmp_hdr_t * icmp_hdr;
    xipaddr_t dest_ip;
    xnet_packet_t* packet;

    uint16_t ip_hdr_size = ip_hdr->hdr_len * 4;
    uint16_t ip_data_size = swap_order16(ip_hdr->total_len) - ip_hdr_size;
    ip_data_size = ip_hdr_size + min(ip_data_size, 64);

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

void xudp_init(void) {
    memset(udp_socket, 0, sizeof(udp_socket));      // Free也是0，所以没什么问题
}

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
    remove_header_for_read(packet, sizeof(xudp_hdr_t));
    if (udp->handler) {
        udp->handler(udp, src_ip, src_port, packet);
    }
}

int xudp_out(xudp_t* udp, xipaddr_t * dest_ip, uint16_t dest_port, xnet_packet_t * packet) {
    xudp_hdr_t* udp_hdr;
    uint16_t checksum;

    if (udp->local_port == 0) {
        xnet_err_t err = xudp_bind(udp, 0);
        if (err < 0) return err;
    }

    add_header_for_send(packet, sizeof(xudp_hdr_t));
    udp_hdr = (xudp_hdr_t*)packet->data;
    udp_hdr->src_port = swap_order16(udp->local_port);
    udp_hdr->dest_port = swap_order16(dest_port);
    udp_hdr->total_len = swap_order16(packet->size);
    udp_hdr->checksum = 0;
    checksum = checksum_peso(&netif_ipaddr, dest_ip, XNET_PROTOCOL_UDP, (uint16_t *) udp_hdr, packet->size);
    udp_hdr->checksum = (checksum == 0) ? 0xFFFF : checksum;
    return xip_out(XNET_PROTOCOL_UDP, dest_ip, packet);;
}

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

void xudp_close(xudp_t *udp) {
    udp->state = XUDP_STATE_FREE;
}

xudp_t* xudp_find(uint16_t port) {
    xudp_t * udp, * end = &udp_socket[XUDP_CFG_MAX_UDP];

    for (udp = udp_socket; udp < end; udp++) {
        if ((udp->state != XUDP_STATE_FREE) && (udp->local_port == port)) {
            return udp;
        }
    }

    return (xudp_t *)0;
}

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

static void tcp_buf_init(xtcp_buf_t *tcp_buf) {
    tcp_buf->tail = tcp_buf->next = tcp_buf->front = 0;
    tcp_buf->data_count = tcp_buf->wait_send_count = 0;
}

static uint16_t tcp_buf_free_count(xtcp_buf_t *tcp_buf) {
    return XTCP_CFG_RTX_BUF_SIZE - tcp_buf->data_count;
}

static void tcp_buf_add_acked_count(xtcp_buf_t *tcp_buf, uint16_t size) {
    tcp_buf->tail += size;
    if (tcp_buf->tail >= XTCP_CFG_RTX_BUF_SIZE) {
        tcp_buf->tail = 0;
    }
    tcp_buf->data_count -= size;
}

static uint16_t tcp_buf_write(xtcp_buf_t *tcp_buf, uint8_t *from, uint16_t size) {
    int i;

    size = min(size, tcp_buf_free_count(tcp_buf));
    for (i = 0; i < size; i++) {
        tcp_buf->data[tcp_buf->front++] = *from++;
        if (tcp_buf->front >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->front = 0;
        }
    }

    tcp_buf->data_count += size;
    tcp_buf->wait_send_count += size;   // 主要给发送使用
    return size;
}

static uint16_t tcp_buf_read(xtcp_buf_t *tcp_buf, uint8_t *to, uint16_t size) {
    int i;

    size = min(size, tcp_buf->data_count);
    for (i = 0; i < size; i++) {
        *to++ = tcp_buf->data[tcp_buf->tail++];
        if (tcp_buf->tail >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->tail = 0;
        }
    }

    tcp_buf->data_count -= size;
    return size;
}

static uint16_t tcp_buf_read_next_send(xtcp_buf_t *tcp_buf, uint8_t *to, uint16_t size) {
    int i;

    size = min(size, tcp_buf->wait_send_count);
    for (i = 0; i < size; i++) {
        *to++ = tcp_buf->data[tcp_buf->next++];
        if (tcp_buf->next >= XTCP_CFG_RTX_BUF_SIZE) {
            tcp_buf->next = 0;
        }
    }

    return size;
}

static uint16_t tcp_recv(xtcp_t *tcp, uint8_t flags, uint8_t *from, uint16_t size) {
    uint16_t read_size = tcp_buf_write(&tcp->rx_buf, from, size);

    tcp->ack += read_size;
    if (flags & (XTCP_FLAG_SYN | XTCP_FLAG_FIN)) {
        tcp->ack++;
    }
    return read_size;
}

static xnet_err_t tcp_send(xtcp_t *tcp, uint8_t flags) {
    xnet_packet_t * packet;
    xtcp_hdr_t * tcp_hdr;
    xnet_err_t err;
    uint16_t data_size = tcp->tx_buf.wait_send_count;
    uint16_t opt_size = (flags & XTCP_FLAG_SYN) ? 4 : 0;     // mss长度

    if (tcp->remote_win) {
        data_size = min(data_size, tcp->remote_win);
        data_size = min(data_size, tcp->remote_mss);
        if (data_size + opt_size > XTCP_HDR_MAX_SIZE) {
            data_size = XTCP_HDR_MAX_SIZE - opt_size;
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

    tcp_buf_read_next_send(&tcp->tx_buf, packet->data + opt_size + sizeof(xtcp_hdr_t), data_size);
    tcp_hdr->checksum = checksum_peso(&netif_ipaddr, &tcp->remote_ip, XNET_PROTOCOL_TCP, (uint16_t *) packet->data, packet->size);
    tcp_hdr->checksum = tcp_hdr->checksum ? tcp_hdr->checksum : 0xFFFF;
    err = xip_out(XNET_PROTOCOL_TCP, &tcp->remote_ip, packet);
    if (err < 0) return err;

    tcp->remote_win -= data_size;       // 同时远端可用窗口减少
    tcp->next_seq += data_size;              // 新发送，序号要增加
    tcp->tx_buf.wait_send_count -= data_size;
    if (flags & (XTCP_FLAG_SYN | XTCP_FLAG_FIN)) {        // FIN占用1个序号
        tcp->next_seq++;
    }
    return XNET_ERR_OK;
}

static xnet_err_t tcp_send_reset (uint32_t sender_seq, uint16_t local_port, xipaddr_t * remote_ip, uint16_t remote_port) {
    xnet_packet_t * packet = xnet_alloc_for_send(sizeof(xtcp_hdr_t));
    xtcp_hdr_t * tcp_hdr = (xtcp_hdr_t *)packet->data;

    tcp_hdr->src_port = swap_order16(local_port);
    tcp_hdr->dest_port = swap_order16(remote_port);
    tcp_hdr->seq = 0;                               // 固定为0即可
    ++sender_seq;
    tcp_hdr->ack = swap_order32(sender_seq);          // 响应指定的发送ack，即对上次发送的包的回应
    tcp_hdr->hdr_flags.all = 0;
    tcp_hdr->hdr_flags.field.hdr_len = sizeof(xtcp_hdr_t) / 4;
    tcp_hdr->hdr_flags.field.flags = XTCP_FLAG_RST | XTCP_FLAG_ACK;
    tcp_hdr->hdr_flags.all = swap_order16(tcp_hdr->hdr_flags.all);
    tcp_hdr->window = 0;
    tcp_hdr->urgent_ptr = 0;
    tcp_hdr->checksum = 0;
    tcp_hdr->checksum = checksum_peso(&netif_ipaddr, remote_ip, XNET_PROTOCOL_TCP, (uint16_t *) packet->data, packet->size);
    tcp_hdr->checksum = tcp_hdr->checksum ? swap_order16(tcp_hdr->checksum) : 0xFFFF;
    return xip_out(XNET_PROTOCOL_TCP, remote_ip, packet);
}

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
            tcp_buf_init(&tcp->rx_buf);
            tcp_buf_init(&tcp->tx_buf);
            tcp->connect_tmo = XTCP_CONNECT_TMO;
            tcp->resend_retry_cnt = XTCP_RESEND_RETRY_CNT;
            tcp->resend_tmo = XTCP_RESEND_TMO;
            return tcp;
        }
    }

    return (xtcp_t *)0;
}

static void tcp_free(xtcp_t* tcp) {
    tcp->state = XTCP_STATE_FREE;
}

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

static void tcp_read_options(xtcp_t * tcp, xtcp_hdr_t * tcp_hdr) {
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

static xtcp_t * tcp_conn_accept(xtcp_t *tcp, xipaddr_t *src_ip, xtcp_hdr_t * tcp_hdr) {
    xnet_err_t err;
    uint32_t ack = swap_order32(tcp_hdr->seq) + 1;

    xtcp_t* new_tcp = tcp_alloc();
    if (!new_tcp) return (xtcp_t *)0;

    new_tcp->state = XTCP_STATE_SYNC_RECVD;
    new_tcp->local_port = tcp->local_port;
    new_tcp->handler = tcp->handler;
    new_tcp->remote_port = swap_order16(tcp_hdr->src_port);    // 肯定会成功的，因为这里端口太多
    new_tcp->remote_ip.addr = src_ip->addr;
    new_tcp->ack = ack;                                     // 对方的seq + syn的长度1，不算选项
    new_tcp->next_seq = new_tcp->unack_seq = tcp_get_init_seq();     // 使用自己的，不用监听套接字的
    new_tcp->remote_win = swap_order16(tcp_hdr->window);
    tcp_read_options(new_tcp, tcp_hdr);         // 读选项，主要是mss

    err = tcp_send(new_tcp, XTCP_FLAG_SYN | XTCP_FLAG_ACK);
    if (err < 0) {
        tcp_free(new_tcp);
        return (xtcp_t *)0;
    }
    return new_tcp;
}

#include <stdio.h>
void xtcp_in(xipaddr_t *remote_ip, xnet_packet_t * packet) {
    xtcp_hdr_t * tcp_hdr = (xtcp_hdr_t *)packet->data;
    uint16_t hdr_flags, hdr_size;
    xtcp_t* tcp;
    uint16_t src_port, dest_port;
    uint32_t ack;

    if (packet->size < sizeof(xtcp_hdr_t)) {
        return;
    }

    src_port = swap_order16(tcp_hdr->src_port);
    dest_port = swap_order16(tcp_hdr->dest_port);
    tcp = tcp_find(remote_ip, src_port, dest_port);
    if (tcp == (xtcp_t *)0) {   // 监听或完全匹配的套接字, 找不到复位
        tcp_send_reset(swap_order32(tcp_hdr->seq), dest_port, remote_ip, src_port);
        return;
    }

    if ((tcp->state != XTCP_STATE_CLOSED) && (tcp->state != XTCP_STATE_LISTEN)) {
        if (tcp->ack != swap_order32(tcp_hdr->seq)) {   // 对方发来的序号和我期望的一致，说明是当前给自己的包，才处理
            return;
        }
    }

    hdr_flags = swap_order16(tcp_hdr->hdr_flags.all);
    hdr_size = (hdr_flags >> 12) * 4;
    if ((tcp->state != XTCP_STATE_LISTEN) && (hdr_flags & XTCP_FLAG_RST)) {        // 复位处理
        tcp->handler(tcp, XTCP_CONN_CLOSED);
        tcp->state = XTCP_STATE_FREE;     // 复位，直接释放掉
        return;
    }

    ack = swap_order32(tcp_hdr->ack);
    tcp->remote_win = swap_order16(tcp_hdr->window);
    switch (tcp->state) {
        case XTCP_STATE_LISTEN: {   // 收到syn, 发syn+ack，进入SYN_RECV状态
            if (hdr_flags & XTCP_FLAG_SYN) {
                xtcp_t* new_tcp = tcp_conn_accept(tcp, remote_ip, tcp_hdr); // 发syn+ack
                if (!new_tcp) {
                    tcp_send_reset(swap_order16(tcp_hdr->seq), tcp->local_port, remote_ip, swap_order16(tcp_hdr->src_port));
                }
            }
            break;
        }
        case XTCP_STATE_SYNC_RECVD: {   // 收到ACK，连接成功. ack丢失重传？
            if (hdr_flags & XTCP_FLAG_ACK) {
                tcp->unack_seq++;
                tcp->state = XTCP_STATE_ESTABLISHED;
                tcp->handler(tcp, XTCP_CONN_CONNECTED);
            }
            break;
        }
        case XTCP_STATE_ESTABLISHED:   // 收发数据 + 接收FIN
            remove_header_for_read(packet, hdr_size);
            if (hdr_flags & (XTCP_FLAG_ACK | XTCP_FLAG_FIN)) {
                uint16_t read_size ;

                if (hdr_flags & XTCP_FLAG_ACK) {    // 有未确认的，确认先
                    if ((tcp->unack_seq <= ack) && (ack <= tcp->next_seq)) {
                        uint16_t curr_ack_size = ack - tcp->unack_seq;
                        tcp_buf_add_acked_count(&tcp->tx_buf, curr_ack_size);
                        tcp->unack_seq += curr_ack_size;
                    }
                }

                // 先读取包里的数据
                read_size = tcp_recv(tcp, (uint8_t)hdr_flags, packet->data, packet->size);
                if (hdr_flags & XTCP_FLAG_FIN) {
                    // 收到关闭请求，发送ACK，同时也发送FIN，同时直接主动关掉
                    // 这样就不必进入CLOSE_WAIT，而是等待对方的ACK
                    tcp->state = XTCP_STATE_LAST_ACK;
                    tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
                } else if (read_size) {
                    // 如果是是收到数据，发ACK响应。
                    tcp_send(tcp, XTCP_FLAG_ACK);
                    tcp->handler(tcp, XTCP_CONN_DATA_RECV);
                } else if (tcp->tx_buf.data_count) {
                    // 没有收到数据，可能是对方发来的ACK。此时，有数据有就发数据，没数据就不理会
                    tcp_send(tcp, XTCP_FLAG_ACK);
                }
            }
            break;
        case XTCP_STATE_FIN_WAIT_1:     // 收到ack后，自己的发送已经关掉，但仍可接收，等待对方发FIN
            if (hdr_flags & XTCP_FLAG_ACK) {
                tcp->state = XTCP_STATE_FIND_WAIT_2;    // 对方也许不想暂时关闭
            } else if (hdr_flags & XTCP_FLAG_FIN) {
                tcp->state = XTCP_STATE_CLOSING;        // 对方同时关闭发送，关掉整个
                tcp_send(tcp, XTCP_FLAG_ACK);
            }
            break;
        case XTCP_STATE_FIND_WAIT_2:    // 自己发送关闭，但仍然能数据接收
            remove_header_for_read(packet, hdr_size);
            if (hdr_flags & (XTCP_FLAG_FIN | XTCP_FLAG_ACK)) {
                uint16_t read_size;

                if (hdr_flags & XTCP_FLAG_ACK) {    // 先处理之前发送的确认, todo: 设置
                    if ((tcp->unack_seq <= ack) && (ack <= tcp->next_seq)) {
                        uint16_t curr_ack_size = ack - tcp->unack_seq;
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
                tcp->state = XTCP_STATE_CLOSED;         // 直接关掉，不处理可能的重发
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

static void tcp_poll(void) {
//    if (xnet_check_tmo(&tcp_timer, XTCP_TIMER_PERIOD)) {
//        // 处理连接，重传超时等问题
//        xtcp_t * start = tcp_socket, * end = tcp_socket + XTCP_CFG_MAX_TCP;
//        for (; start < end; start++) {
//            if (start->state == XTCP_STATE_FREE) {
//                continue;
//            }
//
//            if (--start->resend_tmo == 0) {
//                if (--start->resend_retry_cnt == 0) {
//                    xtcp_close();
//                } else {
//                    tcp_resend(tcp);
//                    start->resend_tmo = XTCP_RESEND_TMO;
//                }
//            }
//        }
//    }
}

void xtcp_init(void) {
    memset(tcp_socket, 0, sizeof(tcp_socket));
    xnet_check_tmo(&tcp_timer, XTCP_TIMER_PERIOD);
}

xtcp_t * xtcp_open(xtcp_handler_t handler) {
    xtcp_t * tcp = tcp_alloc();
    if (!tcp) return (xtcp_t *)0;

    tcp->state = XTCP_STATE_CLOSED;
    tcp->handler = handler;
    return tcp;
}

xnet_err_t xtcp_bind(xtcp_t* tcp, uint16_t local_port) {
    if (tcp->state != XTCP_STATE_CLOSED) {
        return XNET_ERR_STATE;
    }

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

xnet_err_t xtcp_listen(xtcp_t * tcp) {
    if (tcp->state == XTCP_STATE_CLOSED) {
        tcp->state = XTCP_STATE_LISTEN;
        return XNET_ERR_OK;
    }

    return XNET_ERR_STATE;
}

uint16_t xtcp_read(xtcp_t* tcp, uint8_t* data, uint16_t size) {
    return tcp_buf_read(&tcp->rx_buf, data, size);
}

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

xnet_err_t xtcp_close(xtcp_t *tcp) {
    xnet_err_t err;

    if ((tcp->state == XTCP_STATE_ESTABLISHED) | (tcp->state == XTCP_STATE_SYNC_RECVD)) {
        err = tcp_send(tcp, XTCP_FLAG_FIN | XTCP_FLAG_ACK);
        if (err < 0) return err;
        tcp->state = XTCP_STATE_FIN_WAIT_1;
    } else {
        tcp->state = XTCP_STATE_FREE;
    }
    return XNET_ERR_OK;
}

void xnet_init (void) {
    ethernet_init();
    xarp_init();
    xip_init();
    xicmp_init();
    xudp_init();
    xtcp_init();
    srand(xsys_get_time());
}

void xnet_poll(void) {
    ethernet_poll();
    xarp_poll();
    tcp_poll();
}
