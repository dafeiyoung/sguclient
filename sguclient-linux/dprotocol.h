/*
 * =====================================================================================
 *
 *       Filename:  dprotocol.h
 *
 *    Description:  dprotocol.c的头文件，主要含drcom认证的代码（修改拷贝自fsn_server）
 *
 *        Version:  0.18
 *        Created:  
 *       Revision:  none
 *       Compiler:  g++
 *
 *         Author:
 *        Company:
 *
 * =====================================================================================
 */

#ifndef __DPROTOCOL_H
#define __DPROTOCOL_H

#include "public.h"
#include <sys/types.h>
#include <stdio.h> 
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <net/if.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>

#include "md4.h"
#include "md5.h"
#include "sha1.h"

#define DR_SERVER_IP "192.168.127.129"
#define DR_PORT 61440
#define RECV_BUF_LEN 1500
#define RETRY_TIME 15


uint8 drcom_pkt_counter;
int  dstatus;
char dstatusMsg[256];


void init_dial_env(void);
void init_env_d();
void* serve_forever_d(void *args);

typedef struct {//注意端序
    uint8 ChallengeTimer[4];        //LE，本身是一个计数器，但被服务端兼Challenge使用
    uint8 ServerOffsetId[2];        //具体含义未知。推测与服务端内部实现有关
    uint8 ServerClientBufSerno[1];  //具体含义未知。推测与服务端内部实现有关
    uint8 MyDllVer[4];              //LE，与防宽带共享模块有关。推测服务端没有开启此功能，但是这个版本号需要保存
    uint8 U8Counter;                //U8的计数器
}dr_info;

#endif
