/*
 * =====================================================================================
 *
 *       Filename:  dprotocol.c
 *
 *    Description:  主要含drcom认证的代码（修改拷贝自fsn_server）
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

#include "dprotocol.h"
#include "public.h"

char drcom_challenge[4];
char drcom_keepalive_info[4];
char drcom_keepalive_info2[16];
char drcom_misc1_flux[4];
char drcom_misc3_flux[4];

char revData[RECV_BUF_LEN];


static int  sock;
static struct sockaddr_in clientaddr;
static struct sockaddr_in drcomaddr;

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  drcom_crc32
 *  Description:  计算drcom协议中的crc校验值
 *  	  Input:  *data: 指向数据包内容的指针; data_len: 数据包的长度
 *  	 Output:  返回计算出来的校验值
 * =====================================================================================
 */
uint32_t drcom_crc32(char *data, int data_len)
{
	uint32_t ret = 0;
	for (int i = 0; i < data_len;) {
		ret ^= *(unsigned int *) (data + i);
		ret &= 0xFFFFFFFF;
		i += 4;
	}

	// 大端小端的坑
	if(checkCPULittleEndian() == 0) ret = big2little_32(ret);
	ret = (ret * 19680126) & 0xFFFFFFFF;
	if(checkCPULittleEndian() == 0) ret = big2little_32(ret);

	return ret;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  start_request
 *  Description:  发起drcom协议的认证(发送长度为8的数据包)
 *  	  Input:  无
 *  	 Output:  成功返回0；失败返回-1
 * =====================================================================================
 */
int start_request()
{
	const int pkt_data_len = 8;
	char pkt_data[8] =
	    { 0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00 };

	memset(revData, 0, RECV_BUF_LEN);

	int revLen =
	    udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(revData, revLen);
#endif

	if (revData[0] != 0x07)	// Start Response
		return -1;

	memcpy(drcom_challenge, revData + 8, 4);	// Challenge

#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(drcom_challenge, 4);
#endif

	return 0;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  send_login_auth
 *  Description:  发起drcom协议的登录（发送包含用户名、主机名等信息的长度为244的数据包）
 *  	  Input:  无
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int send_login_auth()
{
	const int pkt_data_len = 244;
	char pkt_data[pkt_data_len];

    int data_index = 0;
    int i = 0;
    int user_id_length = strlen(user_id);

    ///////////////  下面开始构造U244  ///////////////
    memset(pkt_data, 0, pkt_data_len);
	/******************  Header  ******************/

	//0x00
	pkt_data[data_index++] = 0x07;	// Code
	pkt_data[data_index++] = 0x01;	//id
	pkt_data[data_index++] = 0xf4;	//len(244低位)
	pkt_data[data_index++] = 0x00;	//len(244高位)
	pkt_data[data_index++] = 0x03;	//step 第几步
	pkt_data[data_index++] = user_id_length;	//uid len  用户ID长度

    /*****************  Address  *****************/

	//0x06 mac
	memcpy(pkt_data + data_index, my_mac, 6);
	data_index += 6;

	//0x0c ip
	memcpy(pkt_data + data_index, &my_ip.sin_addr, 4);
	data_index += 4;

	//0x10 fix(4B) 取决于软件版本
	pkt_data[data_index++] = 0x02;
	pkt_data[data_index++] = 0x22;
	pkt_data[data_index++] = 0x00;
	pkt_data[data_index++] = 0x31;

    /*****************  Protocol  *****************/

	//0x14 challenge
	memcpy(pkt_data + data_index, drcom_challenge, 4);
    pkt_data[data_index++] = 0xc7;
    pkt_data[data_index++] = 0x2f;
    pkt_data[data_index++] = 0x31;
    pkt_data[data_index++] = 0x01;

	//0x18 crc32(之后再填)
	data_index += 4;

    //0x1c 从抓包里看的
	pkt_data[data_index++] = 0x0f;
	pkt_data[data_index++] = 0xbe;
	pkt_data[data_index++] = 0xfe;
	pkt_data[data_index++] = 0xfc;

    /*****************  Account  *****************/

	// 0x20  帐号
	memcpy(pkt_data + data_index, user_id, user_id_length);	
	data_index += user_id_length;

	//0x2b   计算机名
	char temp[100];
	memset(temp, 0, 100); //也续这里可以改小一点
	strcpy(temp, "PC-");
	strcat(temp, user_id);
	memcpy(pkt_data + data_index, temp, 32 - user_id_length);
	data_index += (32 - user_id_length);
    //TODO:这里不知道为什么是这个长度

	data_index += 12;//加上这个后偏移确实是对的

    /*******************  Dns  *******************/
	//0x4b  dns 1 (114.114.114.114)
	pkt_data[data_index++] = 0x72;
	pkt_data[data_index++] = 0x72;
	pkt_data[data_index++] = 0x72;
	pkt_data[data_index++] = 0x72;

	//0x4f
	data_index += 16;

    /*******************  Fixed  *******************/

	//0x5f 固定内容
	pkt_data[data_index++] = 0x94;
	data_index += 3;
	pkt_data[data_index++] = 0x06;
	data_index += 3;
	pkt_data[data_index++] = 0x02;
	data_index += 3;
	pkt_data[data_index++] = 0xf0;
	pkt_data[data_index++] = 0x23;
	data_index += 2;
	pkt_data[data_index++] = 0x02;
	data_index += 2;

	//0x73
	char drcom_ver[12] =
	    { 0x44, 0x72, 0x43, 0x4f, 0x4d, 0x00, 0xb8, 0x01, 0x31, 0x00,
   0x00, 0x00 };// "DrCOM"+版本相关的东西
	memcpy(pkt_data + data_index, drcom_ver, 12);
	data_index += 12;

	//0x7f
	data_index += 16;

	//0x8f
	data_index += 32;

    //0xaf
	data_index += 4;

    //0xb3
	char AuthModuleFileHash[] =
	        "c9145cb8eb2a837692ab3f303f1a08167f3ff64b";  //AuthModuleFileHash from log file
	memcpy(pkt_data + data_index, AuthModuleFileHash, 40);
	data_index += 24;

	//////  至此U224的主体构造完成，下面开始填充其CRC32段  //////

	memset(revData, 0, RECV_BUF_LEN); //TODO:把这行往后移一点

	unsigned int crc = drcom_crc32(pkt_data, pkt_data_len);
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom((char *) &crc, 4);
#endif

	memcpy(pkt_data + 24, (char *) &crc, 4);
	memcpy(drcom_keepalive_info, (char *) &crc, 4);
	// 完成crc32校验，置位0
	pkt_data[28] = 0x00;

#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(pkt_data,pkt_data_len);
#endif

	int revLen =
	    udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(revData, revLen);
#endif

	unsigned char *keepalive_info = revData + 16;
	for (i = 0; i < 16; i++) 
	{
		drcom_keepalive_info2[i] = (unsigned char) ((keepalive_info[i] << (i & 0x07)) + (keepalive_info[i] >> (8 - (i & 0x07))));
	}

#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(drcom_keepalive_info2, 16);
#endif

	return 0;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  send_alive_pkt1
 *  Description:  发起drcom协议的1类型杂项包（发送长度为40的数据包）
 *  	  Input:  无
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int send_alive_pkt1()
{
	const int pkt_data_len = 40;
	char pkt_data[pkt_data_len];
    int data_index = 0;
	memset(pkt_data, 0, pkt_data_len);

    ///////////////  下面开始构造U40  ///////////////

	pkt_data[data_index++] = 0x07;	// Code
	pkt_data[data_index++] = drcom_pkt_id; //id
	pkt_data[data_index++] = 0x28;	//len(40低位)
	pkt_data[data_index++] = 0x00;  //len(40高位)
	pkt_data[data_index++] = 0x0B;	// Step
	pkt_data[data_index++] = 0x01;

	pkt_data[data_index++] = 0xdc;	// Fixed Unknown
	pkt_data[data_index++] = 0x02;

	pkt_data[data_index++] = 0x00;	//每次加一个数//todo 这也没加啊
	pkt_data[data_index++] = 0x00;

	memcpy(pkt_data + 16, drcom_misc1_flux, 4);
    ////////////////  至此U40构造完成  ////////////////
	memset(revData, 0, RECV_BUF_LEN);
	int revLen =
	    udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(revData, revLen);
#endif


	if (revData[0] != 0x07 && revData[0] !=0x4d)	// Misc
		return -1;

	if (revData[5] == 0x06 || revData[0] == 0x4d)	// File
	{
		return send_alive_pkt1();
	} 
	else 
	{
		drcom_pkt_id++;

		memcpy(&drcom_misc3_flux, revData + 16, 4);
		return 0;
	}

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  send_alive_pkt2
 *  Description:  发起drcom协议的3类型杂项包（发送长度为40的数据包）
 *  	  Input:  无
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int send_alive_pkt2()
{
	const int pkt_data_len = 40;
	char pkt_data[pkt_data_len];

	memset(pkt_data, 0, pkt_data_len);
	int data_index = 0;
	pkt_data[data_index++] = 0x07;	// Code
	pkt_data[data_index++] = drcom_pkt_id;
	pkt_data[data_index++] = 0x28;	//len(40低位)
	pkt_data[data_index++] = 0x00;  //len(40高位)

	pkt_data[data_index++] = 0x0B;	// Step
	pkt_data[data_index++] = 0x03;

	pkt_data[data_index++] = 0xdc;	// Fixed Unknown
	pkt_data[data_index++] = 0x02;

	pkt_data[data_index++] = 0x00;	//每次加一个数
	pkt_data[data_index++] = 0x00;


	memcpy(pkt_data + 16, drcom_misc3_flux, 4);
	memcpy(pkt_data + 28, &my_ip, 4);

	memset(revData, 0, RECV_BUF_LEN);
	int revLen =
	    udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(revData, revLen);
#endif

	drcom_pkt_id++;

	memcpy(drcom_misc1_flux, revData + 16, 4);
	return 0;

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  send_alive_begin
 *  Description:  发起drcom协议的心跳包，即“Alive,client to server per 20s”（发送长度为38的数据包）
 *  	  Input:  无
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int send_alive_begin()		//keepalive
{
	const int pkt_data_len = 38;
	char pkt_data[pkt_data_len];
	memset(pkt_data, 0, pkt_data_len);
	int data_index = 0;

	pkt_data[data_index++] = 0xff;	// Code

	memcpy(pkt_data + data_index, drcom_keepalive_info, 4);
	data_index += 19;

	memcpy(pkt_data + data_index, drcom_keepalive_info2, 16);
	data_index += 16;

	memset(revData, 0, RECV_BUF_LEN);
	int revLen =
	    udp_send_and_rev(pkt_data, pkt_data_len, revData);

	return 0;

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_env_d
 *  Description:  初始化socket
 *  	  Input:  无
 *  	 Output:  无
 * =====================================================================================
 */
// init socket
void init_env_d()
{
	memset(&clientaddr, 0, sizeof(clientaddr));
	clientaddr.sin_family = AF_INET;
	clientaddr.sin_port = htons(clientPort);
	clientaddr.sin_addr = my_ip.sin_addr;

	memset(&drcomaddr, 0, sizeof(drcomaddr));
	drcomaddr.sin_family = AF_INET;
	drcomaddr.sin_port = htons(DR_PORT);
	inet_pton(AF_INET, DR_SERVER_IP, &drcomaddr.sin_addr);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if( -1 == sock)
	{
		perror("Create drcom socket failed");
		exit(-1);
	}

	if( 0 != bind(sock, (struct sockaddr *) &clientaddr, sizeof(clientaddr)))
	{
		perror("Bind drcom sock failed");
		exit(-1);
	}
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_dial_env
 *  Description:  初始化拨号环境
 *  	  Input:  无
 *  	 Output:  无
 * =====================================================================================
 */
void init_dial_env()
{
	/* linklayer broadcast address, used to connect the huawei's exchange */
	//const char dev_dest[ETH_ALEN] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
	const char dev_dest[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	
	/* set struct sockaddr_ll for sendto function
	 sa_ll: global value, in "xprotocol.h" */
	sa_ll.sll_family = PF_PACKET;
	sa_ll.sll_protocol = htons(ETH_P_ALL);
	sa_ll.sll_ifindex = if_nametoindex(interface_name);   
	sa_ll.sll_hatype = 0;
	sa_ll.sll_pkttype = PACKET_HOST | PACKET_BROADCAST  | PACKET_MULTICAST;
	memcpy(sa_ll.sll_addr, dev_dest, ETH_ALEN);

	sock =  create_ethhdr_sock(&eth_header); // eth_header,sock: global value

}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  udp_send_and_rev
 *  Description:  发送并接收udp协议的数据包
 *  	  Input:  *send_buf: 指向待发送数据的指针; send_len: 待发送数据的长度; 
 				  *recv_buf: 指向接收缓冲区的指针
 *  	 Output:  返回接收的长度
 * =====================================================================================
 */
int udp_send_and_rev(char* send_buf, int send_len, char* recv_buf)
{
	int nrecv_send, addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in clntaddr;
	int try_times = RETRY_TIME;

	while(try_times--){
		nrecv_send = sendto(sock, send_buf, send_len, 0, (struct sockaddr *) &drcomaddr, addrlen);
		if(nrecv_send == send_len) break;
	}

	try_times = RETRY_TIME;
	while(try_times--){
		nrecv_send = recvfrom(sock, recv_buf, RECV_BUF_LEN, 0,
				(struct sockaddr*) &clntaddr, &addrlen);
		if(nrecv_send > 0 && memcmp(&clntaddr.sin_addr, &drcomaddr.sin_addr, 4) == 0) break;
	}

	return nrecv_send;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  perrorAndSleep
 *  Description:  打印错误信息并休眠
 *  	  Input:  *str: 指向待打印字符串的指针
 *  	 Output:  无
 * =====================================================================================
 */
static void perrorAndSleep(char* str){
	printf("%s\n", str);
	strcpy(dstatusMsg, str);
	dstatus = DOFFLINE;
	sleep(20);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  printAll
 *  Description:  打印错误信息
 *  	  Input:  *str: 指向待打印字符串的指针
 *  	 Output:  无
 * =====================================================================================
 */
static void printAll(char* str){
	printf("drcom %s\n", str);
	strcpy(dstatusMsg, str);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  serve_forever_d
 *  Description:  drcom认证主程序
 *  	  Input:  *args: 传入的参数指针(并不需要)
 *  	 Output:  无
 * =====================================================================================
 */
void* serve_forever_d(void *args)
{
	int ret;

	drcom_pkt_id = 0;
	dstatus = DOFFLINE;
	strcpy(dstatusMsg, "please log on first");

	int needToSendXStart = 1;

	while(1)
	{
		sleep(2);
		if ( xstatus == XOFFLINE)  //802.1x还没有上线
		{
			continue ;
		}

		if ( needToSendXStart )
		{
			ret = start_request();
			if(ret != 0)
			{
				printf("login = start request error\n");
				return NULL;
			}
			needToSendXStart = 0;
		}

		if ( (revData[0] == 0x07) && (revData[2] == 0x10) )  //Misc,Response for alive(or Misc,File)
		{
			printf("Drcom Got: Misc,Response for alive(or Misc,File)\n");
			if ( dstatus == DOFFLINE )  //drcom协议 还没有上线成功
			{
				ret = send_login_auth();
				if(ret != 0)
				{
					printf("login = login error\n");
					continue;
				}
			}
			if ( dstatus == DONLINE )  //drcom协议 已经上线成功
			{
				sleep(3);
				ret = send_alive_pkt1();
				if(ret != 0)
				{
					printf("login = alive phase 1 error\n");
					continue;
				}
			}
		}

		if ( (revData[0] == 0x07) && (revData[2] == 0x30) )  //Misc,3000 
		{
			printf("Drcom Got: Misc,3000\n");
			dstatus = DONLINE;
			printf("@@drcom login successfully!\n");
			ret = send_alive_pkt1();
			if(ret != 0)
			{
				printf("login = alive phase 1 error\n");
				continue;
			}
		}

		if ( (revData[0] == 0x07) && (revData[5] == 0x02) )  //Misc Type2
		{
			printf("Drcom Got: Misc Type2\n");
			ret = send_alive_pkt2();
			if(ret != 0)
			{
				printf("keep = alive phase 2 error\n");
				continue;
			}
		}

		if ( (revData[0] == 0x07) && (revData[5] == 0x04) )  //Misc Type4
		{
			printf("Drcom Got: Misc Type4\n");
			printf("@@drcom keep successfully!\n");
			sleep(8);
			ret = send_alive_begin();
			if(ret != 0)
			{
				printf("keep = begin alive error\n");
				continue;
			}
		}
	}

	close(sock);
	return NULL;
}