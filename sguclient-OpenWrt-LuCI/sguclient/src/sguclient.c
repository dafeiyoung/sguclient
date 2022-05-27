/*
 * =====================================================================================
 *
 *       Filename:  sguclient.c
 *
 *    Description:  sguclient的主文件，主要包含802.1x认证部分的代码
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

#include "sguclient.h"

//#include <assert.h>

#ifndef __linux

static int bsd_get_mac(const char ifname[], uint8_t eth_addr[]);

#endif

/* #####   GLOBLE VAR DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  程序的主控制变量
 *-----------------------------------------------------------------------------*/

pcap_t *pcapHandle;               /* packet capture pcapHandle */
#define      MUTICAST_MAC_DX    0xff, 0xff, 0xff, 0xff, 0xff, 0xff /* 电信802.1x的认证服务器多播地址 */
//电信有些苑亦可用01-d0-f8-00-00-03
//注意电信不可用01-80-c2-00-00-03(交换机不识别，收不到回应)
#define      MUTICAST_MAC_YD 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 /* 移动802.1x的认证服务器多播地址 */

//注意：移动多播地址若改为0xff广播，会增强稳定性，
//但紫竹苑将完全无法使用(交换机不识别，收不到回应)


/* #####   GLOBLE VAR DEFINITIONS   ###################
 *-----------------------------------------------------------------------------
 *  用户信息的赋值变量，由init_argument函数初始化
 *-----------------------------------------------------------------------------*/
int background = 0;            /* 后台运行标记  */
char isp_type = 'D';              /* 运营商类型，默认是电信（西区）  D电信 Y移动  */
char *dev = NULL;               /* 连接的设备名 */
char *username = NULL;
char *password = NULL;

int exit_flag = 0;
int auto_rec = 0;             /* 断线重拨 */
int debug_log_style = 0;      /* 调试模式下详细的日志输出 */
int isReconnecting = 0;       /* 防止掉线后，drcom进程的重新创建之后重复发送EAPOL_START包 */
int timeout_alarm_1x = 1;
int reconnect_times = 0;      /* 超时重连次数 */

/* #####   GLOBLE VAR DEFINITIONS   #########################
 *-----------------------------------------------------------------------------
 *  报文相关信息变量，由init_info函数初始化。
 *-----------------------------------------------------------------------------*/
size_t username_length;
size_t password_length;

uint32_t local_ip;                   /* 网卡IP，网络序，下同 */
uint8_t local_mac[ETHER_ADDR_LEN];  /* MAC地址 */


/* #####   TYPE DEFINITIONS   ######################### */
/*-----------------------------------------------------------------------------
 *  报文缓冲区，由init_frame函数初始化。
 *-----------------------------------------------------------------------------*/
u_char eapol_start[96];            /* 电信EAPOL START报文 */
u_char eapol_logoff[96];           /* 电信EAPOL LogOff报文 */
u_char eapol_keepalive[96];
u_char eap_response_ident[96];     /* 电信EAP RESPON/IDENTITY报文 */
u_char eap_response_md5ch[96];     /* 电信EAP RESPON/MD5 报文 */

u_char eapol_start_YD[60];         /* 移动EAPOL START报文 */
u_char eapol_logoff_YD[60];        /* 移动EAPOL LogOff报文 */
u_char eapol_keepalive_YD[60];
u_char eap_response_ident_YD[60];  /* 移动EAP RESPON/IDENTITY报文 */
u_char eap_response_md5ch_YD[60];  /* 移动EAP RESPON/MD5 报文 */

uint8_t eapGlobalId = 1;  //EAP/EAPOL数据包的ID号，不能改为0，否则无法认证

pthread_t dtid;  //drcom线程的pid

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  printNotification
 *  Description:  打印802.1x的notification信息
 *        Input:  * eap_header: 指向EAP/EAPOL数据包的结构体的指针
 *       Output:  无
 * =====================================================================================
 */
void printNotification(const struct eap_header *eap_header) {
    char *buf = (char *) eap_header;  //拷贝一份EAP/EAPOL数据包供打印
    int i = 0;
    printf("%s\tGot notification: ", getTime());
    for (i = 0; i < 46; ++i)    //准备打印整个EAP/EAPOL数据包
    {
        if ((*buf >= 32) && (*buf <= 127))  //printable
        {
            printf("%c.", *buf);
        }
        buf++;
    }

    printf("\n");
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  generateRandomPort
 *  Description:  产生随机UDP端口号
 *        Input:  无
 *       Output:  返回产生的随机UDP端口号
 * =====================================================================================
 */
unsigned int generateRandomPort() {
    unsigned int random;
    srand((unsigned int) time(0));
    random = 10000 + rand() % 55535;
    return random;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  print_hex
 *  Description:  打印十六进制字节流
 *        Input:  *array: 指向待打印内容的指针; count: 打印长度
 *       Output:  无
 * =====================================================================================
 */
void print_hex(uint8_t *array, int count) {
    int i;
    for (i = 0; i < count; i++) {
        if (!(i % 16))
            printf("\n");
        printf("%02x  .", array[i]);
    }
    printf("\n");
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  getTime
 *  Description:  获取当前系统时间
 *        Input:  无
 *       Output:  char*
 * =====================================================================================
 */
char *getTime() {
    time_t rawTime;
    struct tm *info;
    static char buffer[20];
    time(&rawTime);
    info = localtime(&rawTime);
    strftime(buffer, 20, "%Y-%m-%d %H:%M:%S", info);

    return buffer;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  DrcomAuthenticationEntry
 *  Description:  drcom认证入口
 *        Input:  无
 *       Output:  无
 * =====================================================================================
 */
void DrcomAuthenticationEntry() {

    if (isp_type == 'D') {

        int ret;

        /*
        user_id：drcom udp协议用户名（同802.1x）
        passwd：drcom udp协议密码（同802.1x）
        */
        strcpy(user_id, username);
        strcpy(passwd, password);


        // init ip mac and socks
        init_dial_env();
        init_env_d();

        ret = pthread_create(&dtid, NULL, DrComServerDaemon, NULL);
        if (0 != ret) {
            perror("Failed Creating Drcom Thread!");
            exit(EXIT_FAILURE);
        } else printf("%s\tDrcom Thread Successfully Created.\n", getTime());
    } else return;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  reStartDrcom
 *  Description:  重新创建drcom认证进程
 *        Input:  sleep_time_sec: 睡眠时间(秒)
 *       Output:  无
 * =====================================================================================
 */

void reStartDrcom(int sleep_time_sec) {
    //防止掉线后，drcom进程的重新创建之后重复发送EAPOL_START包
    isReconnecting = 1;

    //重新初始化一些变量
    eapGlobalId = 1;
    memset(revData, 0, sizeof revData);
    memset(revData2, 0, sizeof revData2);

    int ret0 = pthread_cancel(dtid);//杀死线程
    if (0 != ret0) {
        perror("Failed Canceling Drcom Thread!");
        exit(EXIT_FAILURE);
    } else printf("%s\tDrcom Thread Successfully Canceled.\n", getTime());

    pthread_join(dtid, (void **) &ret0);//线程回收

    int ret1 = pthread_create(&dtid, NULL, DrComServerDaemon, NULL);
    if (0 != ret1) {
        perror("Failed Creating Drcom Thread!");
        exit(EXIT_FAILURE);
    } else printf("%s\tDrcom Thread Successfully Created.\n", getTime());

    sleep(sleep_time_sec);

    send_eap_packet(EAPOL_START);

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  auto_reconnect
 *  Description:  802.1x睡眠一段时间后重新发起连接的处理函数
 *        Input:  sleep_time_sec: 睡眠时间(秒)
 *       Output:  无
 * =====================================================================================
 */
void auto_reconnect(int sleep_time_sec, char type) {   //会有三种情况进入此处，一是timeout，二和三分别为移动的EAP_Failure
    if (type == 'T') {   //如果是time_out

        printf("%s\tSGUClient wait package response time out! Check your physical network connection!\n", getTime());
        if (auto_rec) {    //用户启动重连，程序会一直重连

            printf("%s\tThe user enabled automatic reconnection, program will automatically reconnect in 5 secs...\n",
                   getTime());
            //以下为time_out的重连部分，重新初始化一些变量
            eapGlobalId = 1;
            sleep(sleep_time_sec);
            send_eap_packet(EAPOL_START);

        } else {    //用户关闭自动重连，为了防止意外错误，程序一共会重连五次

            if (reconnect_times >= 5) {   //timeout和EAP_Failure重连总次数超过5次
                printf("\n%s\tSGUClient tried reconnect more than 5 times, and all failed.\n", getTime());
                printf("%s\tSGUClient exits now!\n\n", getTime());
                exit(EXIT_FAILURE);
            } else {
                printf("%s\tTo prevent accidental errors, program will automatically reconnect in 5 secs...\n",
                       getTime());
                printf("%s\tThe times of reconnections: %dth.\n", getTime(), reconnect_times + 1);
                reconnect_times++;
                //以下为time_out的重连部分，重新初始化一些变量
                eapGlobalId = 1;
                sleep(sleep_time_sec);
                send_eap_packet(EAPOL_START);
            }

        }

    } else if (type == 'E') {    //如果是EAP_Failure

        fprintf(stdout, "%s\tInfo: Authentication Failed! \n", getTime());
        if (auto_rec) {    //用户启动重连，程序会一直重连

            fprintf(stdout,
                    "%s\tInfo: The user enabled automatic reconnection, program will automatically reconnect in 5 secs...\n",
                    getTime());
            //以下为EAP_Failure的重连部分
            if (isp_type == 'D') {  //电信情况
                reStartDrcom(sleep_time_sec);//电信部分需要重新创建drcom认证进程
            } else if (isp_type == 'Y') {  //移动情况
                //重新初始化一些变量
                eapGlobalId = 1;
                sleep(sleep_time_sec);
                send_eap_packet(EAPOL_START);
            }

        } else {    //用户关闭自动重连，为了防止意外错误，程序一共会重连五次

            if (reconnect_times >= 5) {   //timeout和EAP_Failure重连总次数超过5次
                fprintf(stdout, "\n%s\tInfo: SGUClient tried reconnect more than 5 times, and all failed.\n",
                        getTime());
                fprintf(stdout, "%s\tInfo: SGUClient exits now!\n\n", getTime());
                exit(EXIT_FAILURE);
            } else {
                fprintf(stdout,
                        "%s\tInfo: To prevent accidental errors, program will automatically reconnect in 5 secs...\n",
                        getTime());
                fprintf(stdout, "%s\tInfo: The times of reconnections: %dth.\n", getTime(), reconnect_times + 1);
                reconnect_times++;
                //以下为EAP_Failure的重连部分
                if (isp_type == 'D') {  //电信情况
                    reStartDrcom(sleep_time_sec);//电信部分需要重新创建drcom认证进程
                } else if (isp_type == 'Y') {  //移动情况
                    //重新初始化一些变量
                    eapGlobalId = 1;
                    sleep(sleep_time_sec);
                    send_eap_packet(EAPOL_START);
                }
            }

        }
    } else return;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  time_out_handler
 *  Description:  802.1x等待回应的闹钟超时处理函数
 *        Input:  无
 *       Output:  无
 * =====================================================================================
 */
void time_out_handler() {
    if (isReconnecting == 0) {
        auto_reconnect(5, 'T');  //调用重连函数
    } else if (isReconnecting == 1) {
        sleep(60);//等待1分钟，使drcom进程重新创建并连接
        isReconnecting = 0;//恢复 802.1x等待回应的闹钟超时处理函数
    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  show_usage
 *  Description:  显示sguclient帮助信息
 *        Input:  无
 *       Output:  无
 * =====================================================================================
 */
void show_usage() {
    printf("\n"
           "SGUClient %s \n"
           "\t  -- Supllicant for ShaoGuan University 802.1x Authentication.\n"
           "\t  -- A client can be used on the whole campus.\n"
           "\t     Drcom UDP protocol authentication included(Drcom 5.1.1 X,U62.R110908).\n"
           "\n"
           "  Usage:\n"
           "\tRun under root privilege, usually by `sudo', with your \n"
           "\taccount info in arguments:\n\n"
           "\t-u, --username           802.1x username.\n"
           "\t-p, --password           802.1x password.\n"
           "\t--device              Specify which device to use.\n"
           "\t                      Default is usually eth0.\n\n"
           "\n"
           "  Optional Arguments:\n\n"
           "\t--auto                Enable auto reconnect. Default is disabled.\n"
           "\t--random              Use random UDP client port during Drcom authentication.\n"
           "\t                      Sguclient will generate a random client port to replace 61440.\n"
           "\t                      Only effect the client. Server port will not be affected.\n\n"
           "\t--noheartbeat         Disable timeout alarm clock when waiting for next 802.1x package.\n"
           "\t                      Timeout should be disabled if there is NO 802.1x heart beat package.\n\n"
           "\t--debug               In debug mode, logs are printed in more detail.\n"
           "\t                      And in Sguclient on the OpenWRT side, logs are not cleared automatically.\n\n"

           "\t-b, --background      Program fork to background after authentication.\n\n"

           "\t-i, --isp_type        Specify your ISP type.\n"
           "\t                      'D' for China Telecom(CTCC), 'Y' for China Mobile(CMCC).\n"
           "\t                      Default is D (China Telecom).\n\n"
           "\t-k                    Kill other running SGUClient instance.\n\n"

           "\t-h, --help            Show this help.\n\n"
           "\n"
           "  About SGUClient:\n\n"
           "\tThis program is a C implementation to ShaoGuan University 802.1x Authentication.\n"
           "\tBased on other open-source 802.1x programs,SGUClient has simple goal of replacing \n"
           "\tthe official clients with ONE client. \n\n"
           "\tWarning: This program may not be used for commercial purposes.\n\n"

           "\tSGUClient is a software developed individually, with NO any rela-\n"
           "\tiontship with ShaoGuan University or any other company.\n\n\n"

           "\tBug Report? Please join our QQ group: 638138948\n"
           "\t\t\t\t\t\t\t\t2021-04-13\n",
           SGU_VER);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  get_md5_digest
 *  Description:  calcuate for md5 digest
 * =====================================================================================
 */
char *get_md5_digest(const char *str, size_t len) {
    static md5_byte_t digest[16];
    md5_state_t state;
    md5_init(&state);
    md5_append(&state, (const md5_byte_t *) str, len);
    md5_finish(&state, digest);

    return (char *) digest;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  get_eap_type
 *  Description:  根据报文的动作位返回enum EAPType内定义的报文类型
 *        Input:  *eap_header: 指向EAP\EAPOL报文结构体的指针
 *       Output:  无
 * =====================================================================================
 */
enum EAPType get_eap_type(const struct eap_header *eap_header) {
    switch (eap_header->eap_t) {
        case 0x01:
            if (eap_header->eap_op == 0x01)
                return EAP_REQUEST_IDENTITY;
            if (eap_header->eap_op == 0x04)
                return EAP_REQUETS_MD5_CHALLENGE;
            if (eap_header->eap_op == 0xfa)
                return EAP_REQUEST_MD5_KEEP_ALIVE;
            if (eap_header->eap_op == 0x02)  //802.1x Notification
                return EAP_NOTIFICATION;
            break;

        case 0x03:
            return EAP_SUCCESS;
            break;

        case 0x04:
            return EAP_FAILURE;
    }

    fprintf(stderr, "%s\tIMPORTANT: Unknown Package : eap_t:      %02x.\n"
                    "                               eap_id: %02x.\n"
                    "                               eap_op:     %02x.\n",
            getTime(),
            eap_header->eap_t, eap_header->eap_id,
            eap_header->eap_op);
    exit(EXIT_FAILURE);
    return ERROR;
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  action_by_eap_type
 *  Description:  根据eap报文的类型完成相关的应答
 * =====================================================================================
 */
void action_by_eap_type(enum EAPType pType,
                        const struct eap_header *header,
                        const struct pcap_pkthdr *packetinfo,
                        const uint8_t *packet) {
    if (isp_type == 'D')                //电信部分
    {
        printf("%s\t<CTCC>Received PackType: %d.\n", getTime(), pType);
        switch (pType) {
            case EAP_SUCCESS:
                alarm(0);  //取消闹钟
                reconnect_times = 0;//重置重连计数器
                fprintf(stdout, "%s\tProtocol: EAP_SUCCESS.\n", getTime());
                fprintf(stdout, "%s\tInfo: 802.1x Authorized Access to Network.\n", getTime());
                fprintf(stdout, "%s\tThen please use PPPOE manually to connect to Internet.\n\n", getTime());
                xstatus = XONLINE;
                //print_server_info (packet, packetinfo->caplen);
                if (background) {
                    background = 0;   /* 防止以后误触发 */
                    daemon_init();
                }
                break;

            case EAP_FAILURE:
                alarm(0);  //取消闹钟
                xstatus = XOFFLINE;
                fprintf(stdout, "%s\tProtocol: EAP_FAILURE.\n", getTime());
                auto_reconnect(3, 'E');  //调用重连函数
                break;

            case EAP_REQUEST_IDENTITY:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: REQUEST EAP-Identity.\n", getTime());
                //fprintf(stdout, "DEBUGER@@ current id:%d\n",header->eap_id);
                eapGlobalId = header->eap_id;
                init_frames();
                send_eap_packet(EAP_RESPONSE_IDENTITY);
                break;

            case EAP_REQUETS_MD5_CHALLENGE:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: REQUEST MD5-Challenge(PASSWORD).\n", getTime());
                //fprintf(stdout, "DEBUGER@@ current id:%d\n",header->eap_id);
                eapGlobalId = header->eap_id;
                init_frames();
                fill_password_md5((uint8_t *) header->eap_md5_challenge, header->eap_id);
                send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
                break;

            case EAP_REQUEST_IDENTITY_KEEP_ALIVE:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: REQUEST EAP_REQUEST_IDENTITY_KEEP_ALIVE.\n", getTime());
                //fprintf(stdout, "DEBUGER@@ current id:%d\n",header->eap_id);
                eapGlobalId = header->eap_id;
                init_frames();
                send_eap_packet(EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
                break;

            case EAP_REQUEST_MD5_KEEP_ALIVE:
                break;

            case EAP_NOTIFICATION:
                printNotification(header);
                exit(EXIT_FAILURE);
                break;
            default:
                return;
        }
    } else if (isp_type == 'Y')               //移动部分
    {
        printf("%s\t<CMCC>Received PackType: %d.\n", getTime(), pType);
        switch (pType) {
            case EAP_SUCCESS:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: EAP_SUCCESS.\n", getTime());
                fprintf(stdout, "%s\tInfo: 802.1x Authorized Access to Network.\n", getTime());
                fprintf(stdout, "%s\tThen please use PPPOE manually to connect to Internet.\n\n", getTime());
                if (background) {
                    background = 0;   /* 防止以后误触发 */
                    daemon_init();   /* fork至后台，主程序退出 */
                }
                break;

            case EAP_FAILURE:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: EAP_FAILURE.\n", getTime());
                auto_reconnect(1, 'E');  //调用重连函数
                break;

            case EAP_REQUEST_IDENTITY:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: REQUEST EAP-Identity.\n", getTime());
                //fprintf(stdout, "DEBUGER@@ current id:%d\n",header->eap_id);
                memset(eap_response_ident_YD + 14 + 5, header->eap_id, 1);
                send_eap_packet(EAP_RESPONSE_IDENTITY);
                break;

            case EAP_REQUETS_MD5_CHALLENGE:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: REQUEST MD5-Challenge(PASSWORD).\n", getTime());
                //fprintf(stdout, "DEBUGER@@ current id:%d\n",header->eap_id);
                fill_password_md5((uint8_t *) header->eap_md5_challenge, header->eap_id);
                memset(eap_response_md5ch_YD + 14 + 5, header->eap_id, 1);
                send_eap_packet(EAP_RESPONSE_MD5_CHALLENGE);
                break;

            case EAP_REQUEST_IDENTITY_KEEP_ALIVE:
                alarm(0);  //取消闹钟
                fprintf(stdout, "%s\tProtocol: REQUEST EAP_REQUEST_IDENTITY_KEEP_ALIVE.\n", getTime());
                //fprintf(stdout, "DEBUGER@@ current id:%d\n",header->eap_id);
                eapGlobalId = header->eap_id;
                init_frames();
                memset(eapol_keepalive_YD + 14 + 5, header->eap_id, 1);
                send_eap_packet(EAP_RESPONSE_IDENTITY_KEEP_ALIVE);
                break;

            case EAP_REQUEST_MD5_KEEP_ALIVE:
                break;

            case EAP_NOTIFICATION:
                printNotification(header);
                exit(EXIT_FAILURE);
                break;

            default:
                return;
        }
    } else fprintf(stdout, "%s\tUnknown ISP Type!\n", getTime());
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  send_eap_packet
 *  Description:  根据eap类型发送相应数据包
 * =====================================================================================
 */
void send_eap_packet(enum EAPType send_type) {
    uint8_t *frame_data;
    int frame_length = 0;
    int i = 0;
    switch (send_type) {
        case EAPOL_START: {
            switch (isp_type) {
                case 'D':
                    //电信Start发包部分
                    frame_data = eapol_start;
                    frame_length = sizeof(eapol_start);
                    int j = 2;
                    for (i = 0; i < j; i++)  //模仿官方客户端，认证前发送2次logoff包
                    {
                        fprintf(stdout, "%s\tProtocol: <CTCC>SEND EAPOL-Logoff Twice for CTCC 802.1x Protocol.\n",
                                getTime());
                        if (pcap_sendpacket(pcapHandle, eapol_logoff, sizeof(eapol_logoff)) != 0) {
                            j = j + 1;
                            fprintf(stderr, "%s\tIMPORTANT: Error Sending the packet: %s.\n", getTime(),
                                    pcap_geterr(pcapHandle));
                            continue;
                        }
                    }
                    alarm(WAIT_START_TIME_OUT);  //等待回应
                    fprintf(stdout, "%s\tProtocol: <CTCC>SEND EAPOL-Start Wait for the response.\n", getTime());
                    break;

                case 'Y':
                    //移动Start发包部分
                    frame_data = eapol_start_YD;
                    frame_length = sizeof(eapol_start_YD);
                    alarm(WAIT_START_TIME_OUT);  //等待回应
                    fprintf(stdout, "%s\tProtocol: <CMCC>SEND EAPOL-Start Wait for the response.\n", getTime());
                    break;

                default:
                    fprintf(stdout, "%s\tUnknown ISP Type!\n", getTime());
            }
        }
            break;

        case EAPOL_LOGOFF: {
            switch (isp_type) {
                case 'D':
                    //电信Logoff发包部分
                    frame_data = eapol_logoff;
                    frame_length = sizeof(eapol_logoff);
                    fprintf(stdout, "%s\tProtocol: <CTCC>SEND EAPOL-Logoff.\n", getTime());
                    break;

                case 'Y':
                    //移动Logoff发包部分
                    frame_data = eapol_logoff_YD;
                    frame_length = sizeof(eapol_logoff_YD);
                    fprintf(stdout, "%s\tProtocol: <CMCC>SEND EAPOL-Logoff.\n", getTime());
                    break;

                default:
                    fprintf(stdout, "%s\tUnknown ISP Type!\n", getTime());
            }
        }
            break;

        case EAP_RESPONSE_IDENTITY: {
            switch (isp_type) {
                case 'D':
                    //电信response/identity发包部分
                    frame_data = eap_response_ident;
                    frame_length = 96;
                    if (0 == timeout_alarm_1x) {
                        alarm(0);
                    } else {
                        alarm(WAIT_RESPONSE_TIME_OUT);  //等待回应
                    }
                    fprintf(stdout, "%s\tProtocol: <CTCC>SEND EAP-Response/Identity.\n", getTime());
                    break;

                case 'Y':
                    //移动response/identity发包部分
                    frame_data = eap_response_ident_YD;
                    frame_length = 60;
                    if (0 == timeout_alarm_1x) {
                        alarm(0);
                    } else {
                        alarm(WAIT_RESPONSE_TIME_OUT);  //等待回应
                    }
                    fprintf(stdout, "%s\tProtocol: <CMCC>SEND EAP-Response/Identity\n", getTime());
                    break;

                default:
                    fprintf(stdout, "%s\tUnknown ISP Type!\n", getTime());
            }
        }
            break;

        case EAP_RESPONSE_MD5_CHALLENGE: {
            switch (isp_type) {
                case 'D':
                    //电信response/md5_challenge发包部分
                    frame_data = eap_response_md5ch;
                    frame_length = 96;
                    if (0 == timeout_alarm_1x) {
                        alarm(0);
                    } else {
                        alarm(WAIT_RESPONSE_TIME_OUT);  //等待回应
                    }
                    fprintf(stdout, "%s\tProtocol: <CTCC>SEND EAP-Response/Md5-Challenge\n", getTime());
                    break;
                case 'Y':
                    //移动response/md5_challenge发包部分
                    frame_data = eap_response_md5ch_YD;
                    frame_length = 60;
                    if (0 == timeout_alarm_1x) {
                        alarm(0);
                    } else {
                        alarm(WAIT_RESPONSE_TIME_OUT);  //等待回应
                    }
                    fprintf(stdout, "%s\tProtocol: <CMCC>SEND EAP-Response/Md5-Challenge\n", getTime());
                    break;
                default:
                    fprintf(stdout, "%s\tUnknown ISP Type!\n", getTime());
            }
        }
            break;

        case EAP_RESPONSE_IDENTITY_KEEP_ALIVE: {
            switch (isp_type) {
                case 'D':
                    //电信response_identity_keep_alive发包部分
                    frame_data = eapol_keepalive;
                    frame_length = 96;
                    if (0 == timeout_alarm_1x) {
                        alarm(0);
                    } else {
                        alarm(WAIT_RESPONSE_TIME_OUT);  //等待回应
                    }
                    fprintf(stdout, "%s\tProtocol: <CTCC>SEND EAP_RESPONSE_IDENTITY_KEEP_ALIVE\n", getTime());
                    break;
                case 'Y':
                    //移动response_identity_keep_alive发包部分
                    frame_data = eapol_keepalive_YD;
                    frame_length = 60;
                    if (0 == timeout_alarm_1x) {
                        alarm(0);
                    } else {
                        alarm(WAIT_RESPONSE_TIME_OUT);  //等待回应
                    }
                    fprintf(stdout, "%s\tProtocol: <CMCC>SEND EAP_RESPONSE_IDENTITY_KEEP_ALIVE\n", getTime());
                    break;
                default:
                    fprintf(stdout, "Unknown ISP Type!\n");
            }
        }
            break;
        case EAP_REQUEST_MD5_KEEP_ALIVE:  //useless
            break;

        default:
            fprintf(stderr, "IMPORTANT: Wrong Send Request Type.%02x\n", send_type);
            return;
    }

    if (pcap_sendpacket(pcapHandle, frame_data, frame_length) != 0) {
        fprintf(stderr, "IMPORTANT: Error Sending the packet: %s\n", pcap_geterr(pcapHandle));
        return;
    }
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  get_packet
 *  Description:  pcap的回呼函数，当收到EAPOL报文时自动被调用
 * =====================================================================================
 */
void get_packet(uint8_t *args, const struct pcap_pkthdr *header,
                const uint8_t *packet) {
    /* declare pointers to packet headers */
    //const struct ether_header *ethernet;  /* The ethernet header [1] */
    const struct eap_header *eap_header;

    //ethernet = (struct ether_header*)(packet);   //No needed
    eap_header = (struct eap_header *) (packet + SIZE_ETHERNET);

    enum EAPType p_type = get_eap_type(eap_header);
    action_by_eap_type(p_type, eap_header, header, packet);
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_frames
 *  Description:  初始化发送帧的数据
 * =====================================================================================
 */
void init_frames() {
    uint8_t muticast_mac_DX[] = {MUTICAST_MAC_DX};
    uint8_t muticast_mac_YD[] = {MUTICAST_MAC_YD};

    if (isp_type == 'D')   //电信部分
    {
        int data_index;

        const u_char talier_eap_resp[] = {0x00, 0x44, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        //talier_eap_resp后4位用来填充IP(如果这里IP填入0.0.0.0的话可破IP绑定)
        memcpy((void *) talier_eap_resp + 5, (const void *) &local_ip, 4);       //往response identity里填充IP

        const u_char talier_eap_md5_resp[] = {0x00, 0x44, 0x61, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00};
        //talier_eap_md5_resp后4位用来填充IP(如果这里IP填入0.0.0.0的话可破IP绑定)
        memcpy((void *) talier_eap_md5_resp + 5, (const void *) &local_ip, 4);   //往response identity里填充IP

        /*****  EAPOL Header  *******/
        u_char eapol_header[SIZE_ETHERNET];
        data_index = 0;
        u_short eapol_t = htons(0x888e);
        memcpy(eapol_header + data_index, muticast_mac_DX, 6); /* dst addr. muticast */
        data_index += 6;
        memcpy(eapol_header + data_index, local_mac, 6);    /* src addr. local mac */
        data_index += 6;
        memcpy(eapol_header + data_index, &eapol_t, 2);    /*  frame type, 0x888e*/
        //todo header的结构体已经存在于ethernet.h中(struct ether_header) 使用那个(51@eap_dealer)
        //header 初始化一次后就不会变动了
        /**** EAPol START ****/
        u_char start_data[] = {0x01, 0x01, 0x00, 0x00};
        memset(eapol_start, 0x00, 96);
        memcpy(eapol_start, eapol_header, 14);
        memcpy(eapol_start + 14, start_data, 4);
        memset(eapol_start + 42, 0x01, 1);
        memset(eapol_start + 43, 0x01, 1);

        /****EAPol LOGOFF ****/
        u_char logoff_data[4] = {0x01, 0x02, 0x00, 0x00};
        memset(eapol_logoff, 0x00, 96);
        memcpy(eapol_logoff, eapol_header, 14);
        memcpy(eapol_logoff + 14, logoff_data, 4);

        /****EAPol Keep alive ****/
        u_char keep_data[4] = {0x01, 0x00, 0x00, 0x19};
        u_char temp_data_keepalive[5] = {0x02, eapGlobalId, 0x00, 0x19, 0x01};
        u_char temp_888e_in_keepalive[2] = {0x88, 0x8e};
        memset(eapol_keepalive, 0x00, 96);
        memcpy(eapol_keepalive, muticast_mac_DX, 6);
        memcpy(eapol_keepalive + 6, local_mac, 6);
        memcpy(eapol_keepalive + 12, temp_888e_in_keepalive, 2);
        memcpy(eapol_keepalive + 14, keep_data, 4);
        memcpy(eapol_keepalive + 18, temp_data_keepalive, 5);
        memcpy(eapol_keepalive + 23, username, username_length);
        memcpy(eapol_keepalive + 23 + username_length, talier_eap_resp, 9);

        /* EAP RESPONSE IDENTITY */
        u_char keep_data_response_ident[4] = {0x01, 0x00, 0x00, 0x19};
        u_char temp_data_response_ident[5] = {0x02, eapGlobalId, 0x00, 0x19, 0x01};
        memset(eap_response_ident, 0x00, 96);
        memcpy(eap_response_ident, eapol_header, 14);
        memcpy(eap_response_ident + 14, keep_data_response_ident, 4);
        memcpy(eap_response_ident + 18, temp_data_response_ident, 5);
        memcpy(eap_response_ident + 23, username, username_length);
        memcpy(eap_response_ident + 23 + username_length, talier_eap_resp, 9);

        /** EAP RESPONSE MD5 Challenge **/
        u_char eap_resp_md5_head[10] = {0x01, 0x00,
                                        0x00, 31 + username_length, /* eapol-length */
                                        0x02,
                                        eapGlobalId, /* id to be set */
                                        0x00, 31 + username_length, /* eap-length */
                                        0x04, 0x10};
        memset(eap_response_md5ch, 0x00, 14 + 4 + 6 + 16 + username_length + 14);

        data_index = 0;
        memcpy(eap_response_md5ch + data_index, eapol_header, 14);
        data_index += 14;
        memcpy(eap_response_md5ch + data_index, eap_resp_md5_head, 10);
        data_index += 26; // 剩余16位在收到REQ/MD5报文后由fill_password_md5填充
        memcpy(eap_response_md5ch + data_index, username, username_length);
        data_index += username_length;
        memcpy(eap_response_md5ch + data_index, talier_eap_md5_resp, 9);
    } else if (isp_type == 'Y')   //移动部分
    {

        int data_index;

        u_char eapol_header_YD[SIZE_ETHERNET];
        data_index = 0;
        u_short eapol_t = htons(0x888e);
        memcpy(eapol_header_YD + data_index, muticast_mac_YD, 6); /* dst addr. muticast */
        data_index += 6;
        memcpy(eapol_header_YD + data_index, local_mac, 6);    /* src addr. local mac */
        data_index += 6;
        memcpy(eapol_header_YD + data_index, &eapol_t, 2);    /*  frame type, 0x888e*/

        /**** EAPol START ****/
        u_char start_data_YD[] = {0x01, 0x01, 0x00, 0x00};
        memset(eapol_start_YD, 0xa5, 60);
        memcpy(eapol_start_YD, eapol_header_YD, 14);
        memcpy(eapol_start_YD + 14, start_data_YD, 4);

        /****EAPol LOGOFF ****/
        u_char logoff_data_YD[4] = {0x01, 0x02, 0x00, 0x00};
        memset(eapol_logoff_YD, 0xa5, 60);
        memcpy(eapol_logoff_YD, eapol_header_YD, 14);
        memcpy(eapol_logoff_YD + 14, logoff_data_YD, 4);

        /****EAPol Keep alive ****/
        u_char keep_data_YD[4] = {0x01, 0xfc, 0x00, 0x0c};
        memset(eapol_keepalive_YD, 0xcc, 54 + username_length);
        memcpy(eapol_keepalive_YD, eapol_header_YD, 14);
        memcpy(eapol_keepalive_YD + 14, keep_data_YD, 4);
        memset(eapol_keepalive_YD + 18, 0, 8);
        memcpy(eapol_keepalive_YD + 26, &local_ip, 4);

        /* EAP RESPONSE IDENTITY */
        u_char eap_resp_iden_head_YD[9] = {0x01, 0x00,
                                           0x00, 26 + username_length,  /* eapol_length */
                                           0x02, 0x2c,
                                           0x00, 26 + username_length,       /* eap_length */
                                           0x01};
        char str1[2] = {'#', '0'};        //固定值
        char str2[6] = {'#', '4', '.', '1', '.', '9'};    //版本号
        char buf[64];   //useless

        memset(eap_response_ident_YD, 0xa5, 60);
        data_index = 0;
        memcpy(eap_response_ident_YD + data_index, eapol_header_YD, 14);
        data_index += 14;
        memcpy(eap_response_ident_YD + data_index, eap_resp_iden_head_YD, 9);
        data_index += 9;
        memcpy(eap_response_ident_YD + data_index, username, username_length);
        data_index += username_length;
        memcpy(eap_response_ident_YD + data_index, str1, 2);  //填充 #0
        data_index += 2;
        memcpy(eap_response_ident_YD + data_index, inet_ntop(AF_INET, &local_ip, buf, 32),
               strlen(inet_ntop(AF_INET, &local_ip, buf, 32)));  //填充IP地址
        data_index += strlen(inet_ntop(AF_INET, &local_ip, buf, 32));
        memcpy(eap_response_ident_YD + data_index, str2, 6);  //填充#4.1.9


        /** EAP RESPONSE MD5 Challenge **/
        u_char eap_resp_md5_head_YD[10] = {0x01, 0x00,
                                           0x00, 6 + 16 + username_length, /* eapol-length */
                                           0x02,
                                           0x00, /* id to be set */
                                           0x00, 6 + 16 + username_length, /* eap-length */
                                           0x04, 0x10};

        data_index = 0;
        memcpy(eap_response_md5ch_YD + data_index, eapol_header_YD, 14);
        data_index += 14;
        memcpy(eap_response_md5ch_YD + data_index, eap_resp_md5_head_YD, 10);
        data_index += 26;// 剩余16位在收到REQ/MD5报文后由fill_password_md5填充
        memcpy(eap_response_md5ch_YD + data_index, username, username_length);

    } else fprintf(stdout, "Unknown ISP Type!\n");

}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_password_md5
 *  Description:  给RESPONSE_MD5_Challenge报文填充相应的MD5值。
 *  只会在接受到REQUEST_MD5_Challenge报文之后才进行，因为需要
 *  其中的Key
 * =====================================================================================
 */
void fill_password_md5(uint8_t attach_key[], uint8_t eap_id) {
    if (isp_type == 'D') {
        char *psw_key;
        char *md5;
        psw_key = malloc(1 + password_length + 16);
        psw_key[0] = eap_id;
        memcpy(psw_key + 1, password, password_length);
        memcpy(psw_key + 1 + password_length, attach_key, 16);
        md5 = get_md5_digest(psw_key, 1 + password_length + 16);
        memcpy(eap_response_md5ch + 14 + 10, md5, 16);
        free(psw_key);
    } else if (isp_type == 'Y') {
        char *psw_key = malloc(1 + password_length + 16);
        char *md5;
        psw_key[0] = eap_id;
        memcpy(psw_key + 1, password, password_length);
        memcpy(psw_key + 1 + password_length, attach_key, 16);

#if EAP_DEBUG_ON > 0
        printf("DEBUGER@@: MD5-Attach-KEY:\n");
        print_hex ((u_char*)attach_key, 16);
#endif

        md5 = get_md5_digest(psw_key, 1 + password_length + 16);

        memset(eap_response_md5ch_YD + 14 + 5, eap_id, 1);
        memcpy(eap_response_md5ch_YD + 14 + 10, md5, 16);

        free(psw_key);
    }
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_info
 *  Description:  初始化本地信息。
 * =====================================================================================
 */
void init_info() {
    if (username == NULL || password == NULL) {
        fprintf(stderr, "Error: NO Username(-u) or Password(-p) promoted.\n"
                        "Try sguclient --help for usage.\n");
        exit(EXIT_FAILURE);
    }
    if (dev == NULL) {
        fprintf(stderr, "Error: NO device (--device) promoted.\n"
                        "Try sguclient --help for usage.\n");
        exit(EXIT_FAILURE);
    }

    username_length = strlen(username);
    password_length = strlen(password);

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_pcap
 *  Description:  初始化Pcap过滤器
 * =====================================================================================
 */
void init_pcap() {
    struct bpf_program fp;            /* compiled filter program (expression) */
    char filter_exp[51];         /* filter expression [3] */
    char errbuf[PCAP_ERRBUF_SIZE];  /* error buffer */

    /* open capture device */
    pcapHandle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);

    if (pcapHandle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(pcapHandle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* construct the filter string */
    sprintf(filter_exp, "ether dst %02x:%02x:%02x:%02x:%02x:%02x"
                        " and ether proto 0x888e",
            local_mac[0], local_mac[1],
            local_mac[2], local_mac[3],
            local_mac[4], local_mac[5]);

    /* compile the filter expression */
    if (pcap_compile(pcapHandle, &fp, filter_exp, 1, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(pcapHandle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(pcapHandle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(pcapHandle));
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&fp);

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  get_local_mac
 *  Description:  根据网卡名获得本机MAC地址
 *
 * =====================================================================================
 */
void get_local_mac() {

    struct ifreq ifr;
    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    memcpy(local_mac, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  get_local_ip
 *  Description:  根据网卡名获得本机IP地址
 *
 * =====================================================================================
 */
void get_local_ip() {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) < 0) {
        printf("error\n");
    }

    struct ifaddrs *ifa;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!strcmp(ifa->ifa_name, dev)) {
            if (ifa->ifa_addr != NULL) {
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    memcpy(&local_ip, &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr, sizeof(local_ip));
                    goto found;
                }
            }
        }
    }

    printf("error: can't find ip of %s\n", dev);
    freeifaddrs(ifaddr);
    exit(-1);
    found:
    freeifaddrs(ifaddr);

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  show_local_info
 *  Description:  显示信息
 * =====================================================================================
 */
void show_local_info() {
    char buf[64];
    char *is_auto_buf = "No";
    char *is_debug = "No";
    char *isp_type_buf = "Unknown";
    char *timeout_alarm_1x_buf = "Enabled";
    if (auto_rec) {
        is_auto_buf = "Yes";
    }
    if (debug_log_style) {
        is_debug = "Yes";
    }
    if ('D' == isp_type) {
        isp_type_buf = "China Telecom";
    }
    if ('Y' == isp_type) {
        isp_type_buf = "China Mobile";
    }

    if (0 == timeout_alarm_1x) {
        timeout_alarm_1x_buf = "Disabled";
    }

    printf("######## SGUClient  %s ########\n", SGU_VER);
    printf("Device:\t%s\n", dev);
    printf("MAC:\t%02x:%02x:%02x:%02x:%02x:%02x\n",
           local_mac[0], local_mac[1], local_mac[2],
           local_mac[3], local_mac[4], local_mac[5]);
    printf("IP:\t\t%s\n", inet_ntop(AF_INET, &local_ip, buf, 32));
    printf("Debug:\t%s\n", is_debug);
    printf("ISP Type:\t%s\n", isp_type_buf);
    printf("Auto Reconnect:\t%s\n", is_auto_buf);
    if (isp_type == 'D') {
        printf("Using UDP Port:\t%d\n", clientPort);
    }
    printf("1x Timeout Alarm:\t%s\n", timeout_alarm_1x_buf);
    printf("#####################################\n\n");
}


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_arguments
 *  Description:  初始化和解释命令行的字符串。getopt_long
 * =====================================================================================
 */
void init_arguments(int *argc, char ***argv) {
    /* Option struct for progrm run arguments */
    static struct option long_options[] =
            {
                    {"help",        no_argument,       0,                 'h'},
                    {"background",  no_argument,       &background,       1},
                    {"auto",        no_argument,       &auto_rec,         1},
                    {"noheartbeat", no_argument,       &timeout_alarm_1x, 0},
                    {"debug",       no_argument,       &debug_log_style,  1},
                    {"device",      required_argument, 0,                 2},
                    {"kill",        no_argument,       0,                 'k'},
                    {"random",      no_argument,       0,                 'r'},
                    {"username",    required_argument, 0,                 'u'},
                    {"password",    required_argument, 0,                 'p'},
                    {"isp",         required_argument, 0,                 'i'},
                    {"showinfo",    no_argument,       0,                 's'},
                    {0,             0,                 0,                 0}
            };
    clientPort = 61440;  //初始化时，客户端默认使用61440端口，若启用random则再产生随机端口来替换
    int c;
    while (1) {
        /* getopt_long stores the option index here. */
        int option_index = 0;
        c = getopt_long((*argc), (*argv), "hru:kp:i:s",
                        long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
            case 0:
                break;
            case 'b':
                background = 1;
                break;
            case 2:
                dev = optarg;
                break;
            case 'u':
                username = optarg;
                break;
            case 'p':
                password = optarg;
                break;
            case 's':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'k':
                exit_flag = 1;
                break;
            case 'h':
                show_usage();
                exit(EXIT_SUCCESS);
                break;
            case 'i':
                isp_type = *optarg;
                break;
            case 'r':
                clientPort = generateRandomPort();
                break;
            case '?':
                if (optopt == 'u' || optopt == 'p' || optopt == 'g' || optopt == 'd')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                exit(EXIT_FAILURE);
                break;
            default:
                fprintf(stderr, "Unknown option character `\\x%x'.\n", c);
                exit(EXIT_FAILURE);
        }
    }
}
