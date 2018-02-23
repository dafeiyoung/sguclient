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

#define DR_SERVER_IP "192.168.127.129"
#define DR_PORT 61440
#define RECV_BUF_LEN 1500
#define RETRY_TIME 15


int drcom_pkt_id;
int dstatus;
char dstatusMsg[256];


void init_dial_env(void);
void init_env_d();
int udp_send_and_rev(char* send_buf, int send_len, char* recv_buf);
void* serve_forever_d(void *args);

#endif
