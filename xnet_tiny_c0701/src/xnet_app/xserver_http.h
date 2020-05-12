/**
 * 本源码配套的课程为 - 自己动手写TCIP/IP协议栈 源码
 * 作者：李述铜
 * 课程网址：http://01ketang.cc
 * 版权声明：本源码非开源，二次开发，或其它商用前请联系作者。
 * 注：源码不断升级中，该版本可能非最新版。如需获取最新版，请联系作者。
 */
#ifndef XSERVER_HTTP_H
#define XSERVER_HTTP_H

#include "xnet_tiny.h"

#if defined(__APPLE__)      // 根据实际情况修改
#define XHTTP_DOC_DIR               "/Users/mac/work/git/xnet-tiny/htdocs"  // html文档所在的目录
#else
#define XHTTP_DOC_DIR               "d:/tiny_net"  // html文档所在的目录
#endif

xnet_err_t xserver_http_create(uint16_t port);
void xserver_http_run(void);

#endif // XSERVER_HTTP_H
