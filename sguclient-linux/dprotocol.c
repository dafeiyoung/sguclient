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

dr_info DrInfo;
uint8 revData[RECV_BUF_LEN];
uint8 revData2[RECV_BUF_LEN]; //专门放那个公告,因为我不知道怎么丢弃这份数据
uint8 drcom_pkt_counter;
int  dstatus;
int xstatus;  //802.1x状态

char dstatusMsg[256];

static int  sock;
static struct sockaddr_in drcomaddr;


int SendU8GetChallenge();
int SendU244Login();
int SendU38HeartBeat();
int SendU40DllUpdater(uint8 type);

void U8ResponseParser();
void U244ResponseParser();
void U40ResponseParser();

void FillCheckSum(uint8 *ChallengeFromU8, uint16 Length, uint8 *CheckSum);
uint32 GetU40_3Sum(uint8 *buf);
void DecodeU244Response(uint8* buf);

int udp_send_and_rev(uint8 *send_buf, int send_len, uint8 *recv_buf);

static void perrorAndSleep(char* str);
static void printAll(char* str);


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
 *         Name:  SendU8GetChallenge
 *  Description:  发起drcom协议的认证(发送长度为8的数据包)
 *  	  Input:  无
 *  	 Output:  成功返回0；失败返回-1
 * =====================================================================================
 */
int SendU8GetChallenge()
{
    /*数据包U8，长度固定为8字节，必须在EAP结束后尽快发出
    * +------+----------+----------+-----------------+
    * | 标头  |计数器|长度 |   类型    |   零填充         |
    * +------+-----+----+----------+-----------------+
    * |  07  |  XX | 08 |  00  01  |   00   00   00  |
    * +------+-----+----+----------+-----------------+
    * 计数器:
    *   首次发送时是0,然后就从2开始往后数
    */
	const int pkt_data_len = 8;
	uint8 pkt_data[8] =
	    { 0x07, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00 };
    memcpy(&pkt_data[1],&DrInfo.U8Counter,sizeof(uint8));

	int revLen =
	    udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(revData, revLen);
#endif
    /*数据包U8的响应，长度固定为32字节
    * +------+-----+-----+---------+-------+------------+-----------+
    * | 标头  |计数器|长度|   类型   |算法选择|      零     |    时间码  |
    * +------+-----+----+---------+------+-+------------+-----------+
    * |  07  | XX |10  | 00  02 |   8X  |  00 00 00   |XX XX XX XX |
    * +------+-------+--+--------+----+--+-------------+------------+
    * |    客户端IP   |      某种长度   |       零        |    某种版本 |
    * +--------------+----------------+--------------+-+------------+
    * | c0 a8 XX XX  | a8  ac  00  00 |  00 00 00 00 | dc 02 00 00  |
    * +--------------+----------------+--------------+--------------+
    *  计数器:
    *    原样送回
    *  时间码：
    *    小端序，且最靠近包头的一字节的最后两bit会用来决定U244校验值的产生算法（一共有3种
    *    在新版加密中不接受最后两bit均为0的情况），且整个时间码会被用来当质询值
    *  算法选择：
    *    转换成二进制后，高八位固定为 1000。低八位的最后两位据观察总与上面用来决定U244校验算法的选择位一致
    *  长度：
    *    从其他数据包来看，这里应该是保存包长度用的，但U8的响应包这里却是错的 (0x10=0d16!=0d32)
    *  如果没有特别注明，则所有数据段均为网络端序（也就是大端序）
    */
	if (revData[0] != 0x07 || revData[4] != 0x02)	// Start Response
		return -1;
    U8ResponseParser();
#if DRCOM_DEBUG_ON > 0
	print_hex_drcom(drcom_challenge, 4);
#endif

	return 0;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  SendU244Login
 *  Description:  发起drcom协议的登录（发送包含用户名、主机名等信息的长度为244的数据包）
 *  	  Input:  无
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int SendU244Login()
{
    /*U244，长度固定为32字节，
    * +-----+-----+-----+-------+-------+-------------------+
    * |标头 |计数器| 长度 |  类型  |用户名长|     客户端MAC      |
    * +-----+-----+-----+-------+-------+-------------------+
    * |  07 | 01  | f4  | 00 03 |  0b   | XX XX XX XX XX XX |
    * +-----+-----+--+--+-------+-------+-------------------+
    * |    客户端IP   |  定值1,与版本有关  |  U8[8:12] 质询值   |
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
    uint8 pkt_data[pkt_data_len];

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
    memcpy(pkt_data + data_index, local_mac, 6);
    data_index += 6;

    // 0x000C ip
    memcpy(pkt_data + data_index, &local_ip, 4);
    data_index += 4;

    // 0x0010 fix-options(4B)
    pkt_data[data_index++] = 0x02;
    pkt_data[data_index++] = 0x22;
    pkt_data[data_index++] = 0x00;
    pkt_data[data_index++] = 0x31;

    // 0x0014 challenge
    memcpy(pkt_data + data_index, DrInfo.ChallengeTimer, 4);
    data_index += 4;

    // 0x0018 checkSum

    FillCheckSum(DrInfo.ChallengeTimer, sizeof(DrInfo.ChallengeTimer), &pkt_data[data_index]);
    data_index+=8;

    // 0x0020  帐号 + 计算机名
    int user_id_length = strlen(user_id);
    memcpy(pkt_data + data_index, user_id, user_id_length);
    data_index += user_id_length;
    char UserNameBuffer[15];
    memset(UserNameBuffer, 0, sizeof (UserNameBuffer));
    strcat(UserNameBuffer,"LAPTOP-");
    memcpy(UserNameBuffer+ sizeof("LAPTOP-"),local_mac,sizeof (local_mac));
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
    uint8 drcom_ver[] =
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

   // memset(revData, 0, RECV_BUF_LEN);
    int revLen = udp_send_and_rev(pkt_data, pkt_data_len, revData);

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

    #if DRCOM_DEBUG_ON > 0
        DecodeU244Response(revData);
    	print_hex_drcom(drcom_keepalive_info2, 16);
    #endif
    if (revData[0] != 0x07 || revData[4] != 0x04)
        return -1;
    udp_send_and_rev("0000", 4, revData2);//FIXME:如果不多接收一次,那么后面的程序会被公告影响
    return 0;
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  FillCheckSum
 *  Description:  生成新版协议中U244/U38所需的的校验值
 *  	  Input:  *ChallengeFromU8:指向U8发来的质询值;
 *  	          Length:质询值的长度;
 *  	          *CheckSum:计算完成的校验值(长8个字节)会被直接填入这里
 *  	 Output:  无
 * =====================================================================================
 */
void FillCheckSum(uint8 *ChallengeFromU8, uint16 Length, uint8 *CheckSum){

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

    }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  SendU40DllUpdater
 *  Description:  发送drcom长度为40的数据包，这种包每次出现都是两个来回一组。第一/三个包由客户端发送
 *  	  Input:  type:包类型，可选1或3;
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int SendU40DllUpdater(uint8 type){
    /*数据包U40系列 (上下行均适用)
    * +------+-------+-------+-----+-----+------------+
    * | 标头  | 计数器 |  长度  | 类型 | 步骤 | MyDllVer  |
    * +------+-------+-------+-----+-----+-----------+
    * |  07  |  XX   | 28 00 | 0b  |  0X |  dc 02    |
    * +------+-+-----+-----+-+----++-----+-----------+
    * | 随机值  |   6字节零#  |    时间码    |  四字节零   |
    * +--------+-----------+-------------+-----------+
    * | 00  00 | 00 ... 00 | XX XX XX XX | 00 ... 00 |
    * +--------+----+------+------+------+-----------+
    * |    校验值*   |   客户端IP*   |     八字节零      |
    * +-------------+------+------+------+-----------+
    * | XX XX XX XX | c0 a8 XX XX | 00 00 ... 00 00  |
    * +-------------+-------------+------+-----------+
    *
    * 计数器：
    *  每个来回会加1。注意，如果收到的回包是U40-6，也会加1
    * 步骤：
    *  程序中U40-n的数字n值得就是这个步骤。奇数为客户端->服务端。偶数反之
    * 时间码：
    *  服务端发回数据包时，会更新时间码，需要记录。
    * 6字节零#：
    *  如果是U40-6，则从这里开始格式变为：四字节零(而不是六)，四字节某种长度，四字节某种校验值，四字节零，四字节某种版本，文件载荷
    * 校验值*：
    *  只存在于U40-3，其他包均为0。
    * 客户端IP*：
    *  只存在于U40-3，其他包均为0。
    */
#if DRCOM_VERBOSE_LOG
    printf("Drcom: Sending U40 response phase %d\n",type);
#else
    switch (type) {
        case 1:
            printf(DMSG_SendU40_1);break;
        case 3:
            printf(DMSG_SendU40_3);break;
        default:
            printf("WTF??");break;
    }
#endif
    const int pkt_data_len = 40;
    uint8 pkt_data[pkt_data_len];

    memset(pkt_data, 0, pkt_data_len);
    int data_index = 0;
    pkt_data[data_index++] = 0x07;	// Code
    pkt_data[data_index++] = drcom_pkt_counter;
    pkt_data[data_index++] = 0x28;	//len(40低位)
    pkt_data[data_index++] = 0x00;  //len(40高位)

    pkt_data[data_index++] = 0x0B;	// Step
    pkt_data[data_index++] = type;  // Type

    memcpy(pkt_data+data_index,DrInfo.MyDllVer,2);
    data_index+=2;


    pkt_data[data_index++] = 0x00;	//此处为两位随机生成值，用于分辨同一组包，但置零并不会影响功能
    pkt_data[data_index++] = 0x00;


    memcpy(pkt_data + 16, DrInfo.ChallengeTimer, 4);

    if (type==3){//只有U40-3需要校验值
        uint32  CheckSum = GetU40_3Sum(pkt_data);
        memcpy(pkt_data+24,&CheckSum,4);
    }
    int revLen =
            udp_send_and_rev(pkt_data, pkt_data_len, revData);
#if DRCOM_DEBUG_ON > 0
    print_hex_drcom(revData, revLen);
#endif
    if (revData[0] != 0x07 || revData[4] != 0x0b)
        return -1;

    return 0;
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  SendU38HeartBeat
 *  Description:  发起DrCom协议的心跳包U38
 *  	  Input:  无
 *  	 Output:  成功返回0
 * =====================================================================================
 */
int SendU38HeartBeat(){
    /*数据包U38系列
   * +------+-----------+----------------+
   * | 标头  |  七字节零   | U8[8:12] 质询值 |
   * +------+-----------+----------------+
   * |  ff  | 00 ... 00 |  XX XX  XX XX  |
   * +------+-----------+------+---------+---+
   * |         U38 校验值       |    "Drco"   |
   * +-------------------------+--------+----+
   * | XX XX XX XX XX XX XX XX | 44 72 63 6f |
   * +-------------+-----------+-------------+------+----------------+-------+
   * |    服务端IP  | OffsetId  |    客户端IP   | 常数 | ClientBufSerno | 随机数  |
   * +-------------+-----------+-------------+------+----------------+-------+
   * | c0 a8 7f 81 |  XX   XX  | c0 a8 XX XX |  01  |       XX       | XX XX |
   * +-------------+-----------+-------------+------+----------------+-------+
   * U38校验值:
   *  产生方式与U244的那个应该是一样的
   */

   const int pkt_data_len = 38;
   uint8 pkt_data[pkt_data_len];
   memset(pkt_data, 0, pkt_data_len);
   int data_index = 0;

   pkt_data[data_index++] = 0xff;	// Code

   data_index+=7;
   memcpy(pkt_data + data_index, DrInfo.ChallengeTimer, 4);
   data_index+=4;

   FillCheckSum(DrInfo.ChallengeTimer, 4, pkt_data + data_index);
   data_index += 8;

   char Drco[] =
           { 'D', 'r', 'c', 'o'};
   memcpy(pkt_data + data_index, Drco, 4);
   data_index+=4;

   uint32  ServerIp=inet_addr(DR_SERVER_IP);
   memcpy(pkt_data + data_index,&ServerIp,sizeof (ServerIp));
   data_index+=4;

   memcpy(pkt_data+data_index,DrInfo.ServerOffsetId,2);
   data_index+=2;

   memcpy(pkt_data + data_index, &local_ip, 4);
   data_index += 4;

   pkt_data[data_index++]=0x01;
   memcpy(pkt_data+data_index,DrInfo.ServerClientBufSerno,1);
   data_index+=1;

   pkt_data[data_index++]=0x00;
   pkt_data[data_index++]=0x00;//对包码,用于分辩同一组包

/*
    for (int i = 0; i < 38; ++i) {
        if (i && i % 7 == 0)printf("\n");
        printf("0x%.2x  ", pkt_data[i]);
    }*/

   int revLen =
       udp_send_and_rev(pkt_data, pkt_data_len, revData);
    if (revData[0] != 0x07 || revData[4] != 0x06)	// Start Response
        return -1;
   return 0;

}
/*
* ===  FUNCTION  ======================================================================
*         Name:  GetU40_3Sum
*  Description:  填充U40-3校验值
*  	  Input:  buf，指向数据包内容
*  	 Output:  无
* =====================================================================================
*/
uint32 GetU40_3Sum(uint8 *buf){
    int16_t v7 = 0;
    uint16_t v5 = 0;
    for (int i = 0; i < 20; i++) {
        memcpy(&v7, &buf[2*i], 2);
        v5 ^= v7;
    }
    return (uint32)(v5*711);
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
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(clientPort);
    local.sin_addr.s_addr = local_ip;


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

	if( 0 != bind(sock, (struct sockaddr *) &local, sizeof(local)))
	{
		perror("Bind drcom sock failed");
		exit(-1);
	}
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  init_dial_env
 *  Description:  已弃用
 *  	  Input:  无
 *  	 Output:  无
 * =====================================================================================
 */
void init_dial_env()
{

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
int udp_send_and_rev(uint8 *send_buf, int send_len, uint8 *recv_buf)
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
 *         Name:  U8ResponseParser
 *  Description:  分析U8响应包，提取信息
 *  	  Input:  无
 *  	 Output:  无
 * =====================================================================================
 */
void U8ResponseParser(){
    memcpy(DrInfo.MyDllVer,revData+28,4);
    memcpy(DrInfo.ChallengeTimer,revData+8,4);
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  U244ResponseParser
 *  Description:  分析U244响应包，提取信息
 *  	  Input:  无
 *  	 Output:  无
 * =====================================================================================
 */
void U244ResponseParser(){
    DecodeU244Response(revData);
    uint8 *pBuf = &revData[revData[2] - revData[6]];//指向解密后的加密载荷的起始处
    memcpy(DrInfo.ServerOffsetId,pBuf+8,2);
    memcpy(DrInfo.ServerClientBufSerno,pBuf+15,1);
}
/*
 * ===  FUNCTION  ======================================================================
 *         Name:  U40ResponseParser
 *  Description:  分析U40响应包，提取信息
 *  	  Input:  无
 *  	 Output:  无
 * =====================================================================================
 */
void U40ResponseParser(){
    if (revData[5]==0x06){ //File 类
        //这种包可能是用来更新mydll用的，但是发过来的dll不完整.当然最好不要完整发过来，那个文件看起来不小
        //正常来讲如果不主动发U40-5或发送含有错误版本的U40-1/3时是不会进入这里的
        memcpy(DrInfo.MyDllVer,revData+28,4);//所以这里还是更新一下MyDllVer比较好
        printf("Got dll from U40. Ignored \n");

    }else{
        memcpy(DrInfo.ChallengeTimer, revData + 16, 2);// 只有不是File的时候revData[16:19]才是时间
    }


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
 *         Name:  DrComServerDaemon
 *  Description:  drcom认证主程序
 *  	  Input:  *args: 传入的参数指针(并不需要)
 *  	 Output:  无
 * =====================================================================================
 */
void* DrComServerDaemon(void *args)
{
#if DRCOM_VERBOSE_LOG == 0
    setbuf(stdout, NULL);
#endif
    /*允许取消进程*/
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    /*异步取消， 线程接到取消信号后，立即退出*/
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	int ret;
    strcpy(dstatusMsg, "please log on first");

    drcom_pkt_counter = 0;
	dstatus = DOFFLINE;
	needToSendDrComStart = 1;

    while(1)//todo:检查是否涵盖所有情况
    {
        sleep(2);
        if ( xstatus == XOFFLINE)  //802.1x还没有上线
        {
            continue ;
        }

        if ( needToSendDrComStart )
        {
            printf(DMSG_SendU8);
            ret = SendU8GetChallenge();
            if(ret != 0)
            {
                printf(DMSG_SendU8_Fail);
                return NULL;
            }
            needToSendDrComStart = 0;
            continue;
        }
        //下面开始处理收到的数据包 这是一个以收到的数据包的标志位驱动的状态机//todo:会不会一个包被重复处理多次？
        if ((revData[0]==0x07)&&(revData[4]==0x02)){ //Response for start request U8
            printf(DMSG_GotU8R);

            if (dstatus==DOFFLINE){ //还没有发送U244
                printf(DMSG_SendU244);
                ret = SendU244Login();
                if(ret != 0) {
                    printf(DMSG_SendU244_Fail);
                    continue;
                }

            }else if ( dstatus == DONLINE )  //drcom协议 已经上线成功
            {
                printf(DMSG_SendU38);
                ret = SendU38HeartBeat();
                if(ret != 0)
                {
                    printf(DMSG_SendU38_Fail);
                    continue;
                }
                printf(DMSG_SentU38);
            }
            continue;
        }

        if ( (revData[0] == 0x07) && (revData[4] == 0x04) )  //U244登录成功
        {
            U244ResponseParser();
            printf(DMSG_LoginU244);
            dstatus = DONLINE;
            DrInfo.U8Counter=2;//登录成功后是从2开始数
            ret = SendU40DllUpdater(1);
            if(ret != 0)
            {
                printf(DMSG_SendU40_1_Fail);
                continue;
            }
        }

        if ((revData[0] == 0x07) && (revData[4] == 0x0b) )  //U40-X
        {
            U40ResponseParser();
            if (revData[5] == 0x02){
                printf(DMSG_GotU40_2);
                SendU40DllUpdater(3);
            }else if (revData[5] == 0x04){
                printf(DMSG_FinishU40);
                printf(DMSG_StartInterval);
                sleep(8);
                printf(DMSG_DoneInterval);
                printf(DMSG_SendU8);
                ret = SendU8GetChallenge();
                DrInfo.U8Counter++;
                if(ret != 0)
                {
                    printf(DMSG_SendU8_Fail);
                    return NULL;
                }

            }drcom_pkt_counter++;
        }

        if ((revData[0] == 0x07) && (revData[4] == 0x06) )  //U38-R
        {
            //U38的回包没啥好处理的
            printf(DMSG_GotU38);
            sleep(1);
            ret = SendU40DllUpdater(1);
            if(ret != 0)
            {
                printf(DMSG_SendU40_1_Fail);
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
#if DRCOM_DEBUG_ON>0
    for (int i = 0; i < buf[2]; ++i) {
        if (i && i % 7 == 0)printf("\n");
        printf("0x%.2x  ", buf[i]);
    }
#endif

}