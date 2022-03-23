/*
 * =====================================================================================
 *
 *       Filename:  public.h
 *
 *    Description:  public.c的头文件（修改拷贝自fsn_server）
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

#ifndef __PUBLIC_H_
#define __PUBLIC_H_

#include <stdint.h>
#include <stdio.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netpacket/packet.h>
#include <pthread.h> 
#include <net/if.h>

#define DOFFLINE         0
#define DONLINE          1
//--
#define XOFFLINE         0
#define XONLINE          1

typedef unsigned char   uint8;
typedef unsigned short  uint16;
typedef unsigned int    uint32;

#define DRCOM_DEBUG_ON 1   //Drcom认证部分的调试开关，置1时输出有关调试信息

extern int xstatus;  //802.1x状态
extern struct sockaddr_ll sa_ll;
extern struct ethhdr  eth_header;
extern char nodifyMsg[256];


extern char user_id[32];
extern char passwd[32];
extern char interface_name[32];
extern char listen_ip[32];
extern int listen_port;

extern unsigned int clientPort;

extern struct sockaddr_in my_ip;
extern char my_mac[ETH_ALEN];


void print_mac(char *src);
#if DRCOM_DEBUG_ON > 0
void print_hex_drcom(char *hex, int len);
#endif
int checkCPULittleEndian();
uint32_t big2little_32(uint32_t A);
int create_ethhdr_sock(struct ethhdr * eth_header);
int crt_sock(struct ifreq * ifr);

#endif
