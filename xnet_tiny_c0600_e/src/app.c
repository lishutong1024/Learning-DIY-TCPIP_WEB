/**
 * 本源码配套的课程为 - 自己动手写TCIP/IP协议栈 源码
 * 作者：李述铜
 * 课程网址：http://01ketang.cc
 * 版权声明：本源码非开源，二次开发，或其它商用前请联系作者。
 * 注：源码不断升级中，该版本可能非最新版。如需获取最新版，请联系作者。
 */
#include <stdio.h>
#include "xnet_tiny.h"
#include "xserver_datetime.h"
#include "xserver_http.h"

int main (void) {
    xnet_init();

    xserver_datetime_create(13);
    xserver_datetime_create(14);
    xserver_datetime_create(15);
    xserver_datetime_create(16);
    xserver_http_create(80);

    printf("xnet running\n");
    while (1) {
        xserver_http_run();
        xnet_poll();
    }

    return 0;
}
