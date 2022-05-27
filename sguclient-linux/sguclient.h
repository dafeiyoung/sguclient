/*
 * =====================================================================================
 *
 *       Filename:  sguclient.h
 *
 *    Description:  sguclient.c的头文件
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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <ifaddrs.h>


#include <getopt.h>
#include <unistd.h>
#include "md5.h"
#include "public.h"
#include "dprotocol.h"

/* SGUClient Version */
#define SGU_VER "release 1.0"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* 802.1x部分的调试开关，置1时启用调试 */
#define EAP_DEBUG_ON 0

/* 宏定义 802.1x等待回应数据包的等待超时时间 */
#define WAIT_START_TIME_OUT 15     //等待数据包回应，默认等待15s
#define WAIT_RESPONSE_TIME_OUT 900 //等待数据包回应，默认等待15mins

struct eap_header {
    uint8_t eapol_v;
    uint8_t eapol_t;
    uint16_t eapol_length;
    uint8_t eap_t;
    uint8_t eap_id;
    uint16_t eap_length;
    uint8_t eap_op;
    uint8_t eap_v_length;
    uint8_t eap_md5_challenge[16];
    u_char eap_info_tailer[40];
};

enum EAPType {
    EAPOL_START,
    EAPOL_LOGOFF,
    EAP_REQUEST_IDENTITY,
    EAP_RESPONSE_IDENTITY,
    EAP_REQUEST_IDENTITY_KEEP_ALIVE,
    EAP_RESPONSE_IDENTITY_KEEP_ALIVE,
    EAP_REQUETS_MD5_CHALLENGE,
    EAP_RESPONSE_MD5_CHALLENGE,
    EAP_SUCCESS,
    EAP_FAILURE,
    ERROR,
    EAP_NOTIFICATION,
    EAP_REQUEST_MD5_KEEP_ALIVE = 250
};


void send_eap_packet(enum EAPType send_type);

void show_usage();

char *get_md5_digest(const char *str, size_t len);

void action_by_eap_type(enum EAPType pType,
                        const struct eap_header *header,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet);

void init_frames();

void init_info();

void init_pcap();

void get_local_mac();

void get_local_ip();

void init_arguments(int *argc, char ***argv);

char *getTime();

int debug_log_style;

void fill_password_md5(uint8_t attach_key[], uint8_t eap_id);

int program_running_check();

void daemon_init(void);

void show_local_info();

void printNotification(const struct eap_header *eap_header);

void time_out_handler();

unsigned int generateRandomPort();

void print_hex(uint8_t *array, int count);

void DrcomAuthenticationEntry();

void get_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet);


