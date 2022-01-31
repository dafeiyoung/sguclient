/*
 * =====================================================================================
 *
 *       Filename:  public.c
 *
 *    Description:  定义一些公有的变量和函数，主要供drcom认证使用（修改拷贝自fsn_server）
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

#include "public.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

char EAP_TYPE_ID_SALT[9]  = {0x00, 0x44, 0x61, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};
char EAP_TYPE_MD5_SALT[9] = {0x00, 0x44, 0x61, 0x2a, 0x00, 0xff, 0xff, 0xff, 0xff};

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  print_mac
 *  Description:  以一定格式打印MAC地址
 *        Input:  *src: 待打印的字符串的指针
 *       Output:  无
 * =====================================================================================
 */
void print_mac(char *src)
{
    char mac[32] = "";
    sprintf(mac, "%02x%02x%02x%02x%02x%02x",
                        (unsigned char)src[0],
                        (unsigned char)src[1],
                        (unsigned char)src[2],
                        (unsigned char)src[3],
                        (unsigned char)src[4],
                        (unsigned char)src[5]);

    printf("%s\n", mac);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  print_hex_drcom
 *  Description:  打印十六进制字节流
 *        Input:  *hex: 待打印的内容的指针; len: 打印长度
 *       Output:  无
 * =====================================================================================
 */
#if DRCOM_DEBUG_ON > 0
void print_hex_drcom(char *hex, int len)
{
    printf("print_hex_drcom\n");
    for (int i = 0; i < len; ++i) {
        if (i&&i%16==0){ printf("\n");}
        printf("%.2x ",*((uint8*)hex + i));
    }
    printf("\n\n");

}
#endif

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  checkCPULittleEndian
 *  Description:  检测CPU是否是小端字节序
 *        Input:  无
 *       Output:  是则返回1
 * =====================================================================================
 */
inline int checkCPULittleEndian()
{
    union
    {
        unsigned int a;
        unsigned char b;
    } c;
    c.a = 1;
    return (c.b == 1);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  big2little_32
 *  Description:  大端字节序 转 小端字节序
 *        Input:  A: 待转换的内容
 *       Output:  转换后的内容
 * =====================================================================================
 */
inline uint32_t big2little_32(uint32_t A)
{
    return ((((uint32_t)(A) & 0xff000000) >>24) |
        (((uint32_t)(A) & 0x00ff0000) >> 8) |
        (((uint32_t)(A) & 0x0000ff00) << 8) |
        (((uint32_t)(A) & 0x000000ff) << 24));
}

// create socket and get src ether address
int crt_sock(struct ifreq * ifr)
{
    int s;
    int err;
    s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));

    /*
        assert the ifr->ifr_ifrn.ifrn_name was known before
        interface_name was set in get_from_file(), and saved in /etc/8021.config file
    */
    memset(ifr, 0, sizeof(struct ifreq));
    strncpy(ifr->ifr_ifrn.ifrn_name, interface_name, sizeof(ifr->ifr_ifrn.ifrn_name)); // interface_name: global value, in public.h

    /* get ip address */
    err = ioctl(s, SIOCGIFADDR, ifr);
    if( err < 0)
    {
        perror("ioctl get ip addr error");
        close(s);
        return -1;
    }
    memcpy(&my_ip, &(ifr->ifr_addr), sizeof(my_ip));

    /* get hardware address */
    err = ioctl(s, SIOCGIFHWADDR, ifr);
    if( err < 0)
    {
        perror("ioctl get hw_addr error");
        close(s);
        return -1;
    }

    // refer to: http://blog.chinaunix.net/uid-8048969-id-3417143.html
    err = ioctl(s, SIOCGIFFLAGS, ifr);
    if( err < 0)
    {
        perror("ioctl get if_flag error");
        close(s);
        return -1;
    }


    // check the if's xstatus
    if(ifr->ifr_ifru.ifru_flags & IFF_RUNNING )
    {
        printf("eth link up\n");
    }
    else
    {
        printf("eth link down, please check the eth is ok\n");
        return -1;
    }

    ifr->ifr_ifru.ifru_flags |= IFF_PROMISC;
    err = ioctl(s, SIOCSIFFLAGS, ifr);
    if( err < 0)
    {
        perror("ioctl set if_flag error");
        close(s);
        return -1;
    }

    return s;
}

// the dial route all uses the same fixed eth_header and the same sock
int create_ethhdr_sock(struct ethhdr * eth_header)
{
    /* mac broadcast address, huawei's exchange */
    //const char dev_dest[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
    const char dev_dest[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    /* acquire interface's id and hardaddress based in struct ifreq and mysock*/
    struct ifreq *myifr;
    myifr = (struct ifreq *) malloc( sizeof(struct ifreq) );
    if( NULL == myifr )
    {
        perror("Malloc for ifreq struct failed");
        exit(-1);
    }

    int mysock;
    mysock = crt_sock(myifr);
    if(-1 == mysock)
    {
        perror("Create socket failed");
        exit(-1);
    }

    /* create  eth header
     #define ETH_HLEN 14 */
    memcpy(eth_header->h_dest, dev_dest, ETH_ALEN);
    memcpy(eth_header->h_source, myifr->ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
    memcpy(my_mac, myifr->ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_PAE); // ETH_P_PAE = 0x888e

    // init response salts
    //printf("Drcom host ip: %s\n", inet_ntoa(my_ip.sin_addr));
    memcpy(EAP_TYPE_ID_SALT + sizeof(EAP_TYPE_ID_SALT) - 4, &(my_ip.sin_addr), 4);
    memcpy(EAP_TYPE_MD5_SALT + sizeof(EAP_TYPE_ID_SALT) - 4, &(my_ip.sin_addr), 4);

    free(myifr);
    return mysock;
}
