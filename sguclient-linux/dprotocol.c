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


char drcom_challenge[4];
char drcom_mydllver[2];
char drcom_keepalive_info[4];
char drcom_keepalive_info2[16];
char drcom_u40_timer[2];
char drcom_u40_1_timer[2];
char drcom_u40_2_timer[2];

char revData[RECV_BUF_LEN];

int send_alive_u40(uint8 type);

static int  sock;
static struct sockaddr_in clientaddr;
static struct sockaddr_in drcomaddr;

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  drcom_crc32
 *  Description:  计算drcom协议中的crc校验值 （旧版，已弃用）
 *  	  Input:  *data: 指向数据包内容的指针; data_len: 数据包的长度
 *  	 Output:  返回计算出来的校验值
 * =====================================================================================
 */
uint32_t drcom_crc32(char *data, int data_len)
{
	uint32_t ret = 0;
	int i = 0;
	for (i = 0; i < data_len;) {
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
 *         Name:  send_start_request
 *  Description:  发起drcom协议的认证(发送长度为8的数据包)
 *  	  Input:  无
 *  	 Output:  成功返回0；失败返回-1
 * =====================================================================================
 */
int send_start_request()
{
    /*数据包U8，长度固定为8字节，必须在EAP结束后尽快发出
    * +------+----------+----------+-----------------+
    * | 标头  |   长度   |   类型    |   零填充         |
    * +------+----------+----------+-----------------+
    * |  07  |  00  08  |  00  01  |   00   00   00  |
    * +------+----------+----------+-----------------+
    */
	const int pkt_data_len = 8;
	char pkt_data[8] =
	    { 0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00 };

	memset(revData, 0, RECV_BUF_LEN);

	int revLen =
	    udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(revData, revLen);
#endif
    /*数据包U8的响应，长度固定为32字节
    * +------+-----------+---------+-------+------------+-----------+
    * | 标头  | 错误的长度 |   类型   |算法选择|      零     |    时间码  |
    * +------+----------+---------+------+-+------------+-----------+
    * |  07  |  00  10  | 00  02 |   8X  |  00 00 00   |XX XX XX XX |
    * +------+-------+--+--------+----+--+-------------+------------+
    * |    客户端IP   |      某种长度   |       零        |    某种版本 |
    * +--------------+----------------+--------------+-+------------+
    * | c0 a8 XX XX  | a8  ac  00  00 |  00 00 00 00 | dc 02 00 00  |
    * +--------------+----------------+--------------+--------------+
    *  时间码：
    *    小端序，且最靠近包头的一字节的最后两bit会用来决定U244校验值的产生算法（一共有3种
    *    在新版加密中不接受最后两bit均为0的情况），且整个时间码会被用来当质询值
    *  算法选择：
    *    转换成二进制后，高八位固定为 1000。低八位的最后两位据观察总与上面用来决定U244校验算法的选择位一致
    *  错误的长度：
    *    从其他数据包来看，这里应该是保存包长度用的，但U8的响应包这里却是错的 (0x10=0d16!=0d32)
    *  如果没有特别注明，则所有数据段均为网络端序（也就是大端序）
    */
	if (revData[0] != 0x07)	// Start Response
		return -1;

	memcpy(drcom_challenge, revData + 8, 4);	// Challenge
    memcpy(drcom_challenge, revData +25, 2);    // Ver for U40
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
    /*U244，长度固定为32字节，
    * +-----+-----+-----+-------+-------+-------------------+
    * |标头 |计数器| 长度 |  类型  |用户名长|     客户端MAC      |
    * +-----+-----+-----+-------+-------+-------------------+
    * |  07 | 01  | f4  | 00 03 |  0b   | XX XX XX XX XX XX |
    * +-----+-----+--+--+-------+-------+-------------------+
    * |    客户端IP   |  定值1,与版本有关  |  U8[8:11] 质询值   |
    * +--------------+------------------+-------------------+
    * | c0 a8 XX XX  |  02  22  00  31  |   XX  XX  XX  XX  |
    * +--------------+----------+-------+-------------------+
    * |        U244校验值        |          用户名            |
    * +-------------------------+---------------------------+
    * | XX XX XX XX XX XX XX XX |  XX XX XX  ...  XX XX XX  |
    * +-------------------------+-------------+-------------+
    * |        计算机名          |  客户端DNS1  | 客户端DHCP   |
    * +-------------------------+-------------+-------------+
    * | XX XX XX  ...  XX XX XX | ca 60 80 a6 | 00 00 00 00 |
    * +-------------+-----------+-------------+-+-----------+--+
    * |  客户端DNS2  | 客户端WINS1  | 客户端WINS2   | 系统版本段长度|
    * +-------------+-------------+-------------+--------------+
    * | 72 72 72 72 | 00 00 00 00 | 00 00 00 00 | 94 00 00 00  |
    * +-------------+-------------+-------------+--------------+
    * | MajorVersion| MinorVersion| BuildNumber |  PlatformId  |
    * +-------------+-------------+-------------+--------------+
    * | 06 00 00 00 | 02 00 00 00 | f0 23 00 00 | 02 00 00 00  |
    * +-------------+--+-------+--+---------+---+--------+-----+
    * |    "DrCOM"     | DrVer | DrCustomId | DrNewVerId |
    * +----------------+-------+------------+------------+
    * | 44 72 43 4f 4d |  00   |    b8 01   |   31 00    |
    * +-------------+--+-------+------+-----+-----+------+
    * |  五十四字节零 |客户端验证模块校验码|   零填充   |
    * +-------------+-----------------+-----------+
    * |  00 ... 00  | c9 14 ... f6 4b | 00 ... 00 |
    * +-------------+------------- ---+-----------+
     * U244需要在U8反回后十分钟内发出,否则会掉线。但测试发现，时间码的有效期只有一分钟
     * 计数器：
     *   固定为1，这里延续了laijingwu学长在文章[laijingwu.com/222.html]中对其的标记
     * 长度：
     *   小端序 0x00f4 = 0d244
     * 用户名长度：
     *   0x0b = 0d11
     * 定值1：
     *   小端序，最高字从26变成了31。其他位功能未知
     * U244校验值：
     *   新版从32位变成了64位，具体算法见FillU244CheckSum
     * 计算机名：
     *   也就是主机名，最长32字节
     * 客户端DNS,DHCP,WINS:
     *   统统可以置空
     * 系统版本段：
     *   结构与WIN-API中OSVERSIONINFO结构体完全一致
     *   除了其中的szCSDVersion成员被换成了DrCom自定义的内容
     *   由于DrCom客户端使用GetVersion的姿势不对，从Win8.1后获取到的永远是6.2.9200,所以本段可视为定值
     * "DrCOM"：
     *    是字符串"DrCOM"的ASCII。
     * 客户端验证模块校验码:
     *    来自Log文件中的AuthModuleFileHash段
    */
    const int pkt_data_len = 244;
    char pkt_data[pkt_data_len];

    memset(pkt_data, 0, pkt_data_len);
    int data_index = 0;

    int i = 0;

    // header
    pkt_data[data_index++] = 0x07;	// Code
    pkt_data[data_index++] = 0x01;	//id
    pkt_data[data_index++] = 0xf4;	//len(244低位)
    pkt_data[data_index++] = 0x00;	//len(244高位)
    pkt_data[data_index++] = 0x03;	//step 第几步
    pkt_data[data_index++] = (strlen(user_id)&0xff);	//uid len  用户ID长度

    // 0x0006 mac
    memcpy(pkt_data + data_index, my_mac, 6);
    data_index += 6;

    // 0x000C ip
    memcpy(pkt_data + data_index, &my_ip.sin_addr, 4);
    data_index += 4;

    // 0x0010 fix-options(4B)
    pkt_data[data_index++] = 0x02;
    pkt_data[data_index++] = 0x22;
    pkt_data[data_index++] = 0x00;
    pkt_data[data_index++] = 0x31;

    // 0x0014 challenge
    memcpy(pkt_data + data_index, drcom_challenge, 4);
    data_index += 4;

    // 0x0018 checkSum

    FillU244CheckSum(drcom_challenge, sizeof(drcom_challenge), &pkt_data[data_index]);
    data_index+=8;

    // 0x0020  帐号 + 计算机名
    int user_id_length = strlen(user_id);
    memcpy(pkt_data + data_index, user_id, user_id_length);
    data_index += user_id_length;
    char UserNameBuffer[15];
    memset(UserNameBuffer, 0, sizeof (UserNameBuffer));
    strcat(UserNameBuffer,"LAPTOP-");
    memcpy(UserNameBuffer+ sizeof("LAPTOP-"),my_mac,sizeof (my_mac));
    memcpy(pkt_data +data_index ,UserNameBuffer, sizeof (UserNameBuffer));

    data_index += (32 - user_id_length);//用户名+设备名段总长为32

    //0x004B  dns 1 (202.96.128.166)
    data_index += 11;
    pkt_data[data_index++] = 0xca;
    pkt_data[data_index++] = 0x60;
    pkt_data[data_index++] = 0x80;
    pkt_data[data_index++] = 0xa6;

    //0x0050 dhcp server (全0）
    data_index += 4;

    //0x0054 dns 2 (114.114.114.114)
    pkt_data[data_index++] = 0x72;
    pkt_data[data_index++] = 0x72;
    pkt_data[data_index++] = 0x72;
    pkt_data[data_index++] = 0x72;

    //0x0058 wins server 1/2 (totally useless)
    data_index+=8;

    //0x0060  系统版本
    //pkt_data[data_index++] = 0x94;
    data_index += 3;
    pkt_data[data_index++] = 0x06;
    data_index += 3;
    pkt_data[data_index++] = 0x02;
    data_index += 3;
    pkt_data[data_index++] = 0xf0;
    pkt_data[data_index++] = 0x23;
    data_index += 2;
    pkt_data[data_index++] = 0x02;
    data_index += 3;

    //0x0073 魔法值DrCOM
    char drcom_ver[] =
        { 'D', 'r', 'C', 'O', 'M', 0x00, 0xb8, 0x01, 0x31, 0x00};
    memcpy(pkt_data + data_index, drcom_ver, sizeof(drcom_ver));

    data_index += 64;

    //0x00b4
    char hashcode[] = "c9145cb8eb2a837692ab3f303f1a08167f3ff64b";
    memcpy(pkt_data + data_index, hashcode, 40);


    /* //旧版U244校验码产生方式，已弃用
    unsigned int crc = drcom_crc32(pkt_data, pkt_data_len);
    #if DRCOM_DEBUG_ON > 0
    print_hex_drcom((char *) &crc, 4);
    #endif

    memcpy(pkt_data + 24, (char *) &crc, 4);
    memcpy(drcom_keepalive_info, (char *) &crc, 4);

    // 完成crc32校验，置位0
    pkt_data[28] = 0x00;
    */

    #if DRCOM_DEBUG_ON > 0
    	print_hex_drcom(pkt_data,pkt_data_len);
    #endif

        memset(revData, 0, RECV_BUF_LEN);

    	int revLen =
    	    udp_send_and_rev(pkt_data, pkt_data_len, revData);
    #if DRCOM_DEBUG_ON > 0
    	print_hex_drcom(revData, revLen);
    #endif
    /*数据包U244的响应
    * +------+-------+----+--------+------+----------+
    * | 标头  | 计数器 |长度|  类型  |用户名长| 加密内容长 |
    * +------+-------+----+-------+-------+----------+
    * |  07  |  01   | 30 | 00 04 |   0b  |    20    |
    * +------+-------+------------+-------+----------+
    * |    校验值1    |     未知    |      加密载荷     |
    * +--------------+------------+------------------+
    * | XX XX XX XX  | 01 00 00 00| XX XX ... XX XX  |
    * +--------------+------------+------------------+
    *  校验值1：
    *    U244校验值靠近包头的四字节，先转换为小端序，然后循环右移两次，再转为大端序。
    *    可以猜测服务端的做法是直接赋值到一个uint32里，移完了再赋值回去，没考虑大小端的事情，于是就会出现这种奇观
    *  加密载荷：
    *    这部分收到后的处理和其他部分明显不一样，推测是加密了的，解密算法见 DecodeU244Response函数
    *    解密后的数据只能识别到服务端IP与客户端IP，其他位功能未知
    *
    *  要注意这里会连回两个包，紧接着这个的就是服务端的公告了
    */
    	unsigned char *keepalive_info = revData + 16;
    	for (i = 0; i < 16; i++)
    	{
    		drcom_keepalive_info2[i] = (unsigned char) ((keepalive_info[i] << (i & 0x07)) + (keepalive_info[i] >> (8 - (i & 0x07))));
    	}

    #if DRCOM_DEBUG_ON > 0
        DecodeU244Response(revData);
    	print_hex_drcom(drcom_keepalive_info2, 16);
    #endif

    return 0;
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  FillU244CheckSum
 *  Description:  生成新版协议中U244的校验值
 *  	  Input:  *ChallengeFromU8:指向U8发来的质询值;
 *  	          Length:质询值的长度;
 *  	          *CheckSum:计算完成的校验值，长8个字节
 *  	 Output:  无
 * =====================================================================================
 */
void FillU244CheckSum(uint8 *ChallengeFromU8, uint16 Length, uint8 *CheckSum){

    uint8  Hash[16 + 4]={0};//16 for md4/5 and 20 for sha1
    uint8  ChallengeFromU8Extended[32]={0};
    uint8  type;


    memcpy(ChallengeFromU8Extended, ChallengeFromU8, Length);
    *(uint32*)&ChallengeFromU8Extended[Length]=20161130;//Extending Challenge Code
    Length+=4;

#if DRCOM_DEBUG_ON
    printf("Challange from u8:\n");
    for (int i = 0; i < 4; ++i) {
        printf("0x%.2x  ",*((uint8*)ChallengeFromU8 + i));
    }
    printf("\n\n");
#endif

    type= ChallengeFromU8[0] & 0x03;//这其实是最后两位，但是因为大小端的问题，服务器发出来的时候就跑到最前面了
    if (type==2) {

        md4(ChallengeFromU8Extended, Length, Hash);

        *((uint8 *)CheckSum + 0) = Hash[1];
        *((uint8 *)CheckSum + 1) = Hash[2];
        *((uint8 *)CheckSum + 2) = Hash[8];
        *((uint8 *)CheckSum + 3) = Hash[9];
        *((uint8 *)CheckSum + 4) = Hash[4];
        *((uint8 *)CheckSum + 5) = Hash[5];
        *((uint8 *)CheckSum + 6) = Hash[11];
        *((uint8 *)CheckSum + 7) = Hash[12];

    }else if (type==3){

        sha1(ChallengeFromU8Extended, Length, Hash);

        *((uint8 *)CheckSum + 0) = Hash[2];
        *((uint8 *)CheckSum + 1) = Hash[3];
        *((uint8 *)CheckSum + 2) = Hash[9];
        *((uint8 *)CheckSum + 3) = Hash[10];
        *((uint8 *)CheckSum + 4) = Hash[5];
        *((uint8 *)CheckSum + 5) = Hash[6];
        *((uint8 *)CheckSum + 6) = Hash[15];
        *((uint8 *)CheckSum + 7) = Hash[16];

    }else if (type==1){

        md5(ChallengeFromU8Extended, Length, Hash);

        *((uint8 *)CheckSum + 0) = Hash[2];
        *((uint8 *)CheckSum + 1) = Hash[3];
        *((uint8 *)CheckSum + 2) = Hash[8];
        *((uint8 *)CheckSum + 3) = Hash[9];
        *((uint8 *)CheckSum + 4) = Hash[5];
        *((uint8 *)CheckSum + 5) = Hash[6];
        *((uint8 *)CheckSum + 6) = Hash[13];
        *((uint8 *)CheckSum + 7) = Hash[14];

    }else if (type==0) {

        printf("WARNING:收到旧版U8质询值！ \n");
        //尽管这不应该发生，但此处为了保持一定的兼容性，仍然保留了这两句
        //要注意的是，旧版的校验方式和整个U244的内容有关，详见drcom_crc32函数
        *((uint32 *)CheckSum + 0) = checkCPULittleEndian()==0? big2little_32(20000711):20000711;
        *((uint32 *)CheckSum + 1)= checkCPULittleEndian()==0? big2little_32(126):126;
        //本想绕开大小端的，但那样会打断常量

    }else{//这段是不是可以删掉

        printf("ERROR:收到不支持的U8质询值！\n");

    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  send_alive_u40
 *  Description:  发送drcom长度为40的数据包，这种包每次出现都是两个来回一组。第一/三个包由客户端发送
 *  	  Input:  type:包类型，可选1或3;
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int send_alive_u40(uint8 type){
    const int pkt_data_len = 40;
    char pkt_data[pkt_data_len];

    memset(pkt_data, 0, pkt_data_len);
    int data_index = 0;
    pkt_data[data_index++] = 0x07;	// Code
    pkt_data[data_index++] = drcom_pkt_counter;
    pkt_data[data_index++] = 0x28;	//len(40低位)
    pkt_data[data_index++] = 0x00;  //len(40高位)

    pkt_data[data_index++] = 0x0B;	// Step
    pkt_data[data_index++] = type;  // Type

    memcpy(pkt_data+data_index,drcom_mydllver,2);
    data_index+=2;
    

    pkt_data[data_index++] = 0x00;	//此处为两位随机生成值，用于分辨同一组包，但置零并不会影响功能
    pkt_data[data_index++] = 0x00;


    memcpy(pkt_data + 16, drcom_u40_timer, 4);

    memset(revData, 0, RECV_BUF_LEN);
    int revLen =
            udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
    print_hex_drcom(revData, revLen);
#endif

    drcom_pkt_counter++;
    if (revData[5]==0x06){ //File 类
        printf("Got dll from U40. Ignored \n");
    }else{
        drcom_pkt_counter++;
        memcpy(drcom_u40_timer, revData + 16, 2);// 只有不是File的时候revData[16:18]才是时间
    }
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

    drcom_pkt_counter = 0;
	dstatus = DOFFLINE;
	strcpy(dstatusMsg, "please log on first");

	int needToSendXStart = 1;

	while(1)//todo:检查是否涵盖所有情况
	{
		sleep(2);
		if ( xstatus == XOFFLINE)  //802.1x还没有上线
		{
			continue ;
		}

		if ( needToSendXStart )
		{
			ret = send_start_request();
			if(ret != 0)
			{
				printf("login = start request error\n");
				return NULL;
			}
			needToSendXStart = 0;
		}
        if ((revData[0]=0x07)&&(revData[4]=0x02)){ //Response for start request
            printf("Drcom Got: Response for start request\n");
            if (dstatus==DOFFLINE){ //还没有发送U244
                ret = send_login_auth();
                if(ret != 0)
                {
                    printf("login = login error\n");
                    continue;
                }
            }else if ( dstatus == DONLINE )  //drcom协议 已经上线成功
            {
                sleep(3);
                ret = send_alive_u40(1);//todo：这个不该写在这里
                if(ret != 0)
                {
                    printf("login = alive phase 1 error\n");
                    continue;
                }
            }
        }

		if ( (revData[0] == 0x07) && (revData[4] == 0x04) )  //U244登录成功
		{
			printf("Drcom Got: U244 login response\n");
			dstatus = DONLINE;
			printf("@@drcom login successfully!\n");
			ret = send_alive_u40(1);
			if(ret != 0)
			{
				printf("login = alive phase 1 error\n");
				continue;
			}
		}

        if ((revData[0] == 0x07) && (revData[4] == 0x0b) && (revData[5] == 0x02))  //Misc Type2
		{
			printf("Drcom Got: U40 response phase 2\n");
			ret = send_alive_u40(3);
			if(ret != 0)
			{
				printf("keep = alive phase 2 error\n");
				continue;
			}
		}

		if ( (revData[0] == 0x07) && (revData[5] == 0x04) )  //Misc Type4//todo: what is this?
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
void DecodeU244Response(uint8* buf) {

    uint8 *pBuf = &buf[buf[2] - buf[6]];
    uint16 shift;
    uint8 len = buf[6];
    uint8 tempLeft, tempRight;

    for (int i = 0; i < len; ++i) {
        shift = i & 0x7;
        tempLeft = pBuf[i] << shift;
        tempRight = pBuf[i] >> (8 - shift);
        pBuf[i] = tempRight + tempLeft;
    }
    for (int i = 0; i < len; ++i) {
        if (i && i % 7 == 0)printf("\n");
        printf("0x%.2x  ", pBuf[i]);

    }
}
