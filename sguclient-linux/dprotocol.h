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

#define DRCOM_VERBOSE_LOG 0

#if DRCOM_VERBOSE_LOG
#define DMSG_SendU8          "Drcom: Sending login request U8\n"
#define DMSG_SendU8_Fail     "DrCom: 初始数据包发送失败!\n"
#define DMSG_GotU8R          "Drcom: Got response for start request U8\n"
#define DMSG_SendU244        "Drcom: Sending login request U244\n"
#define DMSG_SendU244_Fail   "Drcom: Login request U244 failed\n"
#define DMSG_SendU38         "Drcom: Sending heart beat U38\n"
#define DMSG_SendU38_Fail    "Drcom: Heart beat U38 failed\n"
#define DMSG_SentU38         "Drcom: Sent heart beat U38\n"
#define DMSG_LoginU244       "Drcom: Got U244 login response, U244 login success\n"
#define DMSG_SendU40_1_Fail  "Drcom: U40 phase 1 error\n"
#define DMSG_GotU40_2        "Drcom: Got U40 response phase 2\n"
#define DMSG_FinishU40       "Drcom: Got U40 response phase 4, U40 cycle done\n"
#define DMSG_StartInterval   "Drcom: Waiting for 8s before sending next U8\n"
#define DMSG_DoneInterval    "Drcom: 8s Done\n"
#define DMSG_GotU38          "Drcom: Got U38 response. Keep alive cycle done!\n"
#else
#define DMSG_SendU8         "\nDrcom: U8↑--"
#define DMSG_SendU8_Fail    " U38↑✖ "
#define DMSG_GotU8R         "↓✓ "
#define DMSG_SendU244       " U244↑--"
#define DMSG_SendU244_Fail  "✖ !!\n"
#define DMSG_SendU38        " U38↑"
#define DMSG_SendU38_Fail   " =✖ !!\n"
#define DMSG_SentU38        "✓--"
#define DMSG_LoginU244      "↓✓    "
#define DMSG_SendU40_1_Fail "U40-1↑✖ !!\n "
#define DMSG_GotU40_2       "--2↓"
#define DMSG_FinishU40      "--4↓U40✓"
#define DMSG_StartInterval  "   Wait 8s..."
#define DMSG_DoneInterval   "✓ "
#define DMSG_GotU38         "↓ ♡↺✓ "
#define DMSG_SendU40_1      "U40-1↑"
#define DMSG_SendU40_3      "--3↑"
#endif
#define DR_SERVER_IP "192.168.127.129"
#define DR_PORT 61440
#define RETRY_TIME 15
#define RECV_BUF_LEN 1500

extern uint8 revData[RECV_BUF_LEN];
extern uint8 revData2[RECV_BUF_LEN]; //专门放那个公告,因为我不知道怎么丢弃这份数据
extern char dstatusMsg[256];


void init_dial_env(void);
void init_env_d();

void* DrComServerDaemon(void *args);

typedef struct {//注意端序
    uint8 ChallengeTimer[4];        //LE，本身是一个计数器，但被服务端兼Challenge使用
    uint8 ServerOffsetId[2];        //具体含义未知。推测与服务端内部实现有关
    uint8 ServerClientBufSerno[1];  //具体含义未知。推测与服务端内部实现有关
    uint8 MyDllVer[4];              //LE，与防宽带共享模块有关。推测服务端没有开启此功能，但是这个版本号需要保存
    uint8 U8Counter;                //U8的计数器
}dr_info;

#endif
