/**
 * 本源码配套的课程为 - 自己动手写TCIP/IP协议栈 源码
 * 作者：李述铜
 * 课程网址：http://01ketang.cc
 * 版权声明：本源码非开源，二次开发，或其它商用前请联系作者。
 * 注：源码不断升级中，该版本可能非最新版。如需获取最新版，请联系作者。
 */

/**
 * 使用pcap来模拟一个网卡
 * 本部分代码可独立编译，不依赖xnet
 */
#ifndef PCAP_DRIVER_H
#define PCAP_DRIVER_H 

#include <pcap.h>
#include <stdint.h>

// 主-次版本号
#define NPCAP_VERSION_M             0
#define NPCAP_VERSION_N             9986

typedef void (*irq_handler_t)(void* arg, uint8_t is_rx, const uint8_t* data, uint32_t size);

pcap_t* pcap_device_open(const char* ip, const uint8_t *mac_addr, uint8_t poll_mode);
void pcap_device_close(pcap_t* pcap);
uint32_t pcap_device_send(pcap_t* pcap, const uint8_t* buffer, uint32_t length);
uint32_t pcap_device_read(pcap_t* pcap, uint8_t* buffer, uint32_t length);

#endif //PCAP_DRIVER_H
