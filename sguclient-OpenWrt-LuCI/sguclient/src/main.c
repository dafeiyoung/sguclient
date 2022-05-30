/*
 * =====================================================================================
 *
 *       Filename:  main.c
 *
 *    Description:  sguclient的主文件，包含主函数
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include "sguclient.h"
#include "public.h"
#include "dprotocol.h"

#define LOCKFILE "/var/run/sguclient.pid"        /* 锁文件 */
#define LOCKMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)

static void signal_interrupted(int signo);

static void flock_reg();

extern pcap_t *pcapHandle;
extern int exit_flag;

int hLockFile;           /* 锁文件的描述字 */


/*
 * ===  FUNCTION  ======================================================================
 *         Name:  daemon_init
 *  Description:  准备fork至后台
 *        Input:  无
 *       Output:  无
 * =====================================================================================
 */
void daemon_init(void) {
    pid_t pid;
    int fd0;

    if ((pid = fork()) < 0)
        perror("Fork");
    else if (pid != 0) {
        fprintf(stdout, "%s\tInfo: SGUClient Forked background with PID: [%d].\n\n", getTime(), pid);
        exit(0);
    }
    setsid();        /* become session leader */
    assert(0 == chdir("/tmp"));        /* change working directory */
    umask(0);        /* clear our file mode creation mask */
    flock_reg();

    fd0 = open("/dev/null", O_RDWR);
    dup2(fd0, STDIN_FILENO);
    dup2(fd0, STDERR_FILENO);
    dup2(fd0, STDOUT_FILENO);
    close(fd0);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  program_running_check
 *  Description:  检测是否已经有锁（检测程序是否已经在运行）
 *        Input:  无
 *       Output:  若无锁则返回0; 若有锁则返回锁着文件的进程pid
 * =====================================================================================
 */
int program_running_check() {
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;

    //打开锁文件
    hLockFile = open(LOCKFILE, O_RDWR | O_CREAT, LOCKMODE); //开启后毋须关闭
    if (hLockFile < 0) {
        perror("无法确认锁文件状态");
        exit(1);
    }
    //尝试获得文件锁
    if (fcntl(hLockFile, F_GETLK, &fl) < 0) {
        perror("fcntl_get");
        exit_sguclient();
    }

    if (exit_flag) {
        if (fl.l_type != F_UNLCK) {
            if (kill(fl.l_pid, SIGINT) == -1)
                perror("kill");
            fprintf(stdout, "%s\tInfo: Kill Signal Sent to PID %d .\n", getTime(), fl.l_pid);
        } else
            fprintf(stderr, "%s\tInfo: NO SGUClient Running.\n", getTime());
        close(hLockFile);
        exit_sguclient();
    }

    //没有锁，则给文件加锁，否则返回锁着文件的进程pid
    if (fl.l_type == F_UNLCK) {
        flock_reg();
        return 0;
    }

    return fl.l_pid;
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  flock_reg
 *  Description:  sguclient加锁防止重复运行
 *        Input:  无
 *       Output:  无
 * =====================================================================================
 */
void flock_reg() {
    char buf[16];
    struct flock fl;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    fl.l_pid = getpid();

    //阻塞式的加锁
    if (fcntl(hLockFile, F_SETLKW, &fl) < 0) {
        perror("fcntl_reg");
        exit(1);
    }

    ftruncate(hLockFile, 0);
    lseek(hLockFile, 0, SEEK_SET);
    sprintf(buf, "%ld", (long) getpid()); //把pid写入锁文件
    write(hLockFile, buf, strlen(buf) + 1);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  signal_interrupted
 *  Description:  处理Ctrl+C用户取消信号，退出整个程序
 *        Input:  signo: 捕获的信号
 *       Output:  无
 * =====================================================================================
 */
static void signal_interrupted(int signo) {
    fprintf(stdout, "\n\n%s\tInfo: USER Interrupted.\n", getTime());
    send_eap_packet(EAPOL_LOGOFF);
    fprintf(stdout, "%s\tInfo: The program successfully exited.\n\n", getTime());
    pcap_breakloop(pcapHandle);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  main
 *  Description:  主函数
 *        Input:  argc: 传入参数的个数; **argv: 传入参数
 *       Output:  成功返回1
 * =====================================================================================
 */
int main(int argc, char **argv) {

    //关闭标准输出缓冲区，避免导致延迟输出到文件
    setbuf(stdout, NULL);

    //初始化并解释程序的启动参数
    init_arguments(&argc, &argv);

    //检测程序的副本运行（文件锁）
    int ins_pid;
    if ((ins_pid = program_running_check())) {
        fprintf(stderr, "%s\tError Report: SGUClient Already Running with PID %d .\n", getTime(), ins_pid);
        fprintf(stdout, "%s\tInfo: run 'sudo kill %d' or %s -k before re-running SGUClient'.\n\n", getTime(), ins_pid,
                argv[0]);
        exit_sguclient();
    }

    //初始化用户信息
    init_info();

    //初始化日志格式
    init_logStyle();

    //初始化设备，打开网卡，获得Mac、IP等信息
    get_local_mac();
    get_local_ip();

    //初始化Pcap
    init_pcap();

    //初始化802.1x发送帧的缓冲区
    init_frames();

    signal(SIGINT, signal_interrupted);
    signal(SIGTERM, signal_interrupted);
    signal(SIGALRM, time_out_handler);   //注册超时闹钟，超时则自动调用time_out_handler函数
    show_local_info();

    //Drcom认证入口
    DrcomAuthenticationEntry();

    //发出第一个上线请求报文
    send_eap_packet(EAPOL_START);

    //进入回呼循环。以后的动作由回呼函数get_packet驱动，
    //直到pcap_break_loop执行，退出程序。
    pcap_loop(pcapHandle, -2, get_packet, NULL);   /* main pcap loop */
    pcap_close(pcapHandle);
    return 0;
}




