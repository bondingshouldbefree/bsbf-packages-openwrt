/******************************************************************************
  @file    qfirehose.c
  @brief   entry point.

  DESCRIPTION
  QFirehoe Tool for USB and PCIE of Meig wireless cellular modules.

  INITIALIZATION AND SEQUENCING REQUIREMENTS
  None.

  ---------------------------------------------------------------------------
  Copyright (c) 2016 - 2020 Meig Wireless Solution, Co., Ltd.  All Rights Reserved.
  Meig Wireless Solution Proprietary and Confidential.
  ---------------------------------------------------------------------------
******************************************************************************/
#include <getopt.h>
#include <grp.h>
#include <sys/types.h>
#include <pwd.h>
#ifdef USE_IPC_MSG
#include <sys/msg.h>
#include <sys/ipc.h>
#endif

#include "usb_linux.h"
#include "md5.h"
/*zqy add support at operation 20210319 start*/
#include <fcntl.h>      /*文件控制定义*/
#include <stdio.h>      /*标准输入输出定义*/
#include <stdlib.h>     /*标准函数库定义*/
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <termios.h>    /*PPSIX 终端控制定义*/
#include <unistd.h>     /*Unix 标准函数定义*/
#include "getdevinfo.h"
#include <sys/types.h>
#include <stdbool.h>
#define FALSE  -1
#define TRUE   0
/*zqy add support at operation 20210319 end*/
/*
[PATCH 3.10 27/54] usb: xhci: Add support for URB_ZERO_PACKET to bulk/sg transfers
https://www.spinics.net/lists/kernel/msg2100618.html

commit 4758dcd19a7d9ba9610b38fecb93f65f56f86346
Author: Reyad Attiyat <reyad.attiyat@gmail.com>
Date:   Thu Aug 6 19:23:58 2015 +0300

    usb: xhci: Add support for URB_ZERO_PACKET to bulk/sg transfers

    This commit checks for the URB_ZERO_PACKET flag and creates an extra
    zero-length td if the urb transfer length is a multiple of the endpoint's
    max packet length.
*/
unsigned qusb_zlp_mode = 1; //MT7621 donot support USB ZERO PACKET
unsigned q_erase_all_before_download = 0;
int sahara_main(const char *firehose_dir, void *usb_handle, int edl_mode_05c69008);
int firehose_main (const char *firehose_dir, void *usb_handle, unsigned qusb_zlp_mode);
int stream_download(const char *firehose_dir, void *usb_handle, unsigned qusb_zlp_mode);
int retrieve_soft_revision(void *usb_handle, uint8_t *mobile_software_revision, unsigned length);
int usb2tcp_main(const void *usb_handle, int tcp_port, unsigned qusb_zlp_mode);
int ql_capture_usbmon_log(const char* usbmon_logfile);
void ql_stop_usbmon_log();

static MODEM_INFO  curr_modem_info;//zqy add 
//process vals
static long long all_bytes_to_transfer = 0;    //need transfered
static long long transfer_bytes = 0;        //transfered bytes;

const char *g_part_upgrade = NULL;

int switch_to_edl_mode(void *usb_handle) {
    //DIAG commands used to switch the Qualcomm devices to EDL (Emergency download mode)
    unsigned char edl_cmd[] = {0x4b, 0x65, 0x01, 0x00, 0x54, 0x0f, 0x7e};
    //unsigned char edl_cmd[] = {0x3a, 0xa1, 0x6e, 0x7e}; //DL (download mode)
    unsigned char *pbuf = malloc(512);
    int rx_len;

     do {
        rx_len = qusb_noblock_read(usb_handle, pbuf , 512, 0, 1000);
    } while (rx_len > 0);

    dbg_time("switch to 'Emergency download mode'\n");
    rx_len = qusb_noblock_write(usb_handle, edl_cmd, sizeof(edl_cmd), sizeof(edl_cmd), 3000, 0);
    if (rx_len < 0)
        return 0;

    do {
        rx_len = qusb_noblock_read(usb_handle, pbuf , 512, 0, 3000);
        if (rx_len == sizeof(edl_cmd) && memcmp(pbuf, edl_cmd, sizeof(edl_cmd)) == 0) {
            dbg_time("successful, wait module reboot\n");
            free(pbuf);
            return 1;
        }
    } while (rx_len > 0);

    free(pbuf);
    return 0;
}
#if 1
/*zqy add support at operation 20210319 start*/
/*******************************************************************
* 名称： OpenDev
* 功能：  打开串口并返回串口设备文件描述
* 入口参数：fd    :文件描述符     port :串口号(ttyS0,ttyS1,ttyS2)
* 出口参数：正确返回为1，错误返回为0
*******************************************************************/
int OpenDev(char* port)
{
    //printf("open tty port %s\n", port);
    int fd = open( port, O_RDWR);//|O_NOCTTY|O_NDELAY
   // printf("open tty port after %d",fd);
    if (FALSE == fd) {
        printf("Can't Open Serial Port\n");
        dbg_time("Can't Open Serial Port\n");

        return 0;
    }
    //恢复串口为阻塞状态
    //printf("test 1");
    if(fcntl(fd, F_SETFL, 0) < 0) {
        printf("fcntl failed!\n");
        return 0;
    }
    //printf("test 2 %d",fd);
    return fd;
}

/*******************************************************************
* 名称： CloseDev
* 功能： 关闭串口并返回串口设备文件描述
* 入口参数： fd    :文件描述符     port :串口号(ttyS0,ttyS1,ttyS2)
* 出口参数： oid
*******************************************************************/

void CloseDev(int fd)
{
    close(fd);
}

/*******************************************************************
* 名称：UART0_Set
* 功能：设置串口数据位，停止位和效验位
* 入口参数：fd        串口文件描述符
*                              speed     串口速度
*                              flow_ctrl   数据流控制
*                           databits   数据位   取值为 7 或者8
*                           stopbits   停止位   取值为 1 或者2
*                           parity     效验类型 取值为N,E,O,,S
*出口参数： 正确返回为1，错误返回为0
*******************************************************************/

int UART0_Set(int fd,int speed,int flow_ctrl,int databits,int stopbits,int parity)
{
    int   i = 0;
    int   speed_arr[] = { B115200, B19200, B9600, B4800, B2400, B1200, B300};
    int   name_arr[] = {115200,  19200,  9600,  4800,  2400,  1200,  300};

    struct termios options;

    /*tcgetattr(fd,&options)得到与fd指向对象的相关参数，并将它们保存于options,该函数还可以测试配置是否正确，该串口是否可用等。若调用成功，函数返回值为0，若调用失败，函数返回值为1.
    */
    if ( tcgetattr( fd,&options) !=  0) {
        printf("SetupSerial 1");
        return 0;
    }

    //设置串口输入波特率和输出波特率
    for( i= 0;  i < sizeof(speed_arr)/ sizeof(int);  i++) {
        if (speed == name_arr[i]) {
            cfsetispeed(&options, speed_arr[i]);
            cfsetospeed(&options, speed_arr[i]);
        }
    }

    //修改控制模式，保证程序不会占用串口
    options.c_cflag |= CLOCAL;
    //修改控制模式，使得能够从串口中读取输入数据
    options.c_cflag |= CREAD;

    //设置数据流控制
    switch(flow_ctrl) {
    case 0://不使用流控制
        options.c_cflag &= ~CRTSCTS;
        break;

    case 1://使用硬件流控制
        options.c_cflag |= CRTSCTS;
        break;
    case 2://使用软件流控制
        options.c_cflag |= IXON | IXOFF | IXANY;
        break;
    }
    //设置数据位
    //屏蔽其他标志位
    options.c_cflag &= ~CSIZE;
    switch (databits) {
    case 5:
        options.c_cflag |= CS5;
        break;
    case 6:
        options.c_cflag |= CS6;
        break;
    case 7:
        options.c_cflag |= CS7;
        break;
    case 8:
        options.c_cflag |= CS8;
        break;
    default:
        fprintf(stderr,"Unsupported data size\n");
        return 0;
    }
    //设置校验位
    switch (parity) {
    case 'n':
    case 'N': //无奇偶校验位。
        options.c_cflag &= ~PARENB;
        options.c_iflag &= ~INPCK;
        break;
    case 'o':
    case 'O'://设置为奇校验
        options.c_cflag |= (PARODD | PARENB);
        options.c_iflag |= INPCK;
        break;
    case 'e':
    case 'E'://设置为偶校验
        options.c_cflag |= PARENB;
        options.c_cflag &= ~PARODD;
        options.c_iflag |= INPCK;
        break;
    case 's':
    case 'S': //设置为空格
        options.c_cflag &= ~PARENB;
        options.c_cflag &= ~CSTOPB;
        break;
    default:
        fprintf(stderr,"Unsupported parity\n");
        return 0;
    }
    // 设置停止位
    switch (stopbits) {
    case 1:
        options.c_cflag &= ~CSTOPB;
        break;
    case 2:
        options.c_cflag |= CSTOPB;
        break;
    default:
        fprintf(stderr,"Unsupported stop bits\n");
        return 0;
    }

    //修改输出模式，原始数据输出
    options.c_oflag &= ~OPOST;

    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);//我加的

    //设置等待时间和最小接收字符
    options.c_cc[VTIME] = 1; /* 读取一个字符等待1*(1/10)s */
    options.c_cc[VMIN] = 1; /* 读取字符的最少个数为1 */

    //如果发生数据溢出，接收数据，但是不再读取 刷新收到的数据但是不读
    tcflush(fd,TCIFLUSH);

    //激活配置 (将修改后的termios数据设置到串口中）
    if (tcsetattr(fd,TCSANOW,&options) != 0) {
        printf("com set error!\n");
        dbg_time("com set error!\n");

        return 0;
    }
    return 1;
}

/*******************************************************************
* 名称：  UART0_Init()
* 功能： 串口初始化
* 入口参数：        fd       :  文件描述符
*               speed  :  串口速度
*                              flow_ctrl  数据流控制
*               databits   数据位   取值为 7 或者8
*                           stopbits   停止位   取值为 1 或者2
*                           parity     效验类型 取值为N,E,O,,S
*
* 出口参数：        正确返回为1，错误返回为0
*******************************************************************/
int UART0_Init(int fd, int speed,int flow_ctrl,int databits,int stopbits,int parity)
{
    //设置串口数据帧格式
    if (UART0_Set(fd,115200,0,8,1,'N') == FALSE) {
        return 0;
    } else {
        return 1;
    }
}

/*******************************************************************
* 名称： UART0_Recv
* 功能： 接收串口数据
* 入口参数：        fd                  :文件描述符
*                              rcv_buf     :接收串口中数据存入rcv_buf缓冲区中
*                              data_len    :一帧数据的长度
* 出口参数：        正确返回为1，错误返回为0
*******************************************************************/
int UART0_Recv(int fd, char *rcv_buf,int data_len)
{
    int len,fs_sel;
    fd_set fs_read;

    struct timeval time;

    FD_ZERO(&fs_read);
    FD_SET(fd,&fs_read);

    time.tv_sec = 8;
    time.tv_usec = 0;

    //使用select实现串口的多路通信
    fs_sel = select(fd+1,&fs_read,NULL,NULL,&time);
    switch(fs_sel) {
    case -1:
        printf("select error!\n");
        return -1;
    case 0:
        printf("respond time out!\n");
        return -1;
    default:
        len = read(fd,rcv_buf,data_len);
        if(len == -1) {
            printf("read error,len = %d fs_sel = %d\n",len,fs_sel);
            return -1;
        }
        return len;
    }
}

/********************************************************************
* 名称：UART0_Send
* 功能：发送数据
* 入口参数：        fd                  :文件描述符
*                              send_buf    :存放串口发送数据
*                              data_len    :一帧数据的个数
* 出口参数：        正确返回为1，错误返回为0
*******************************************************************/
int UART0_Send(int fd, const char *send_buf,int data_len)
{
    int len = 0;

    len = write(fd,send_buf,data_len);
    if (len == data_len ) {
        return len;
    } else {
        tcflush(fd,TCOFLUSH);
        return 0;
    }

}

/*[zhaopf@meigsmart-2020-0630]fixed for return ERROR { */
#define NUM_ELEMS(x) (sizeof(x)/sizeof(x[0]))
#if 0
int strStartsWith(const char *line, const char *prefix)
{
    for ( ; *line != '\0' && *prefix != '\0' ; line++, prefix++) {
        if (*line != *prefix) {
            return 0;
        }
    }

    return *prefix == '\0';
}
#endif

static const char * s_finalResponsesError[] = {
    "ERROR",
    "+CMS ERROR:",
    "+CME ERROR:",
    "NO CARRIER", /* sometimes! */
    "NO ANSWER",
    "COMMAND NOT SUPPORT",
};
static int isFinalResponseError(const char *line)
{
    size_t i;

    for (i = 0 ; i < NUM_ELEMS(s_finalResponsesError) ; i++) {
        if (NULL != strstr(line, s_finalResponsesError[i])) {
            return 1;
        }
    }

    return 0;
}
/*[zhaopf@meigsmart-2020-0630]fixed for return ERROR } */
bool SendATCMD(int fd, const char* cmd,int cmdLength, char* rev, int revLength, bool bNeedRev)
{
    int len=0;
    int i =0;
    for(i = 0; i < 5; i++) {
        len = UART0_Send(fd, cmd,cmdLength);
        if(len > 0) {
            dbg_time("[AT]->%s", cmd);
            break;
        } else {
            dbg_time("[AT]->failed!\n");
            return false;
        }

    }
    len=0;
    if(!bNeedRev) {
        return true;
    }
    sleep(0.5);
    while (1) { //循环读取数据
        len = read(fd,rev,revLength);
        if(len > 0) {
            rev[len] = '\0';
            dbg_time("[AT]<-%s\n", rev);
            /*[zhaopf@meigsmart-2020-0630]fixed for return ERROR { */
            if(isFinalResponseError(rev)){
                return false;
            }
            if(NULL==strstr(rev,"OK")) { //如果返回信息中没有找到OK，则返回false
            /*[zhaopf@meigsmart-2020-0630]fixed for return ERROR } */
                continue;
            }
            return true;
        } else {
            dbg_time("cannot receive data!\n");
            exit(EXIT_FAILURE);
        }
    }


    return true;
}


void str_trim_crlf(char *str) //去除\r\n
{
    char *p = &str[strlen(str)-1];
    while (*p == '\r' || *p == '\n')
        *p-- = '\0';

}

void executeCMD(const char *cmd, char *result)
{
    char buf_ps[1024];
    char ps[1024]= {0};
    FILE *ptr;
    strcpy(ps, cmd);
    if((ptr=popen(ps, "r"))!=NULL) {
        while(fgets(buf_ps, 1024, ptr)!=NULL) {
            strcat(result, buf_ps);
            if(strlen(result)>1024)
                break;
        }
        pclose(ptr);
        ptr = NULL;
    } else {
        printf("popen %s error\n", ps);
    }
}

int Add_OptionDriver()
{
    pid_t  status;
    int i;
    status = system("modprobe option");
    char cmd_buff[128] = { 0x0 };
    if (!WIFEXITED(status)) {
        printf("modprobe option Fail,please try again!\n");
        dbg_time("modprobe option Fail,please try again!\n");
    } else {
        //printf("modprobe option Success!\n");
        dbg_time("modprobe option Success!\n");
    }

    sleep(1);
    for(i = 0; i < MEIG_PRODUCT_LIST_SIZE; i++) {
        // status = system("echo 05c6 f601 >/sys/bus/usb-serial/drivers/option1/new_id");
        memset(cmd_buff, 0x0, sizeof(cmd_buff));
        sprintf(cmd_buff, "echo %s %s >/sys/bus/usb-serial/drivers/option1/new_id", meig_product_list[i].vid, meig_product_list[i].pid);
        printf("write cmd:%s\n", cmd_buff);
        status = system(cmd_buff);
        if (!WIFEXITED(status)) {
            printf("write cmd Fail,please try again!\n");
            dbg_time("write cmd Fail,please try again!\n");

            return 0;
        } else {
            printf("write cmd Success!\n");
            dbg_time("write cmd Success!\n");
        }


    }


    return 1;
}

bool upgrade_check()
{
    int retrytimes = 10;
    int fd = -1, err;
    bool getIMEI=false;
    char rcv_buf[512]= {0};
    const char *at_check = "at\r\n";
    const char *at_imei = "AT+LCTSN=0,7\r\n";

    if(Add_OptionDriver()) {
        dbg_time("Insmod option driver Success!\n");
    } else {
        dbg_time("Insmod option driver fail,please check!\n");

        return 0;
    }
    

    while(retrytimes-- > 0) {
        dbg_time("upgrade check wait %d times\n", (retrytimes+1));
        fd = OpenDev("/dev/ttyUSB2");
        if(fd <= 0) {
            dbg_time("OpenDev Fail!\n");
            CloseDev(fd);
            continue ;
        }

        sleep(1);
       // printf("upgrad_check 1 \n");
        err = UART0_Init(fd,115200,0,8,1,'N');
       // printf("upgrad_check 2 \n");
        if(0 == err) {
            dbg_time("Set Port Exactly!\n");
            CloseDev(fd);
            continue ;
        }
       // printf("upgrad_check 3 \n");
        sleep(1);
        if(!SendATCMD(fd, at_check ,  strlen(at_check) ,  rcv_buf, sizeof(rcv_buf), true)) {
            dbg_time("Send at command failed!\n");
            CloseDev(fd);
            continue ;
        }
        sleep(1);
        memset(rcv_buf, 0, sizeof(rcv_buf));
        if(!SendATCMD(fd, at_imei, strlen(at_imei), rcv_buf, sizeof(rcv_buf),true)) {
            dbg_time("read imei failed!\n");
            CloseDev(fd);
            continue ;
        }
        if(NULL==strstr(rcv_buf, "LCTSN")) {
            dbg_time("NV Verify Fail!\n");
            CloseDev(fd);
            continue ;
        } else {
            getIMEI=true;
            dbg_time("read imei ok\n");
            CloseDev(fd);
            break;
        }

    }
    if((!getIMEI) && fd > 0){
         CloseDev(fd);
    }
    return getIMEI;
}



bool upgrade_check_cfun()
{
    int retrytimes = 10;
    int fd = -1, err;
    bool getcfun=false;
    char rcv_buf[512]= {0};
    const char *at_check = "at\r\n";
    const char *at_cfun = "at+cfun?\r\n";
    

    while(retrytimes-- > 0) {
        dbg_time("upgrade check wait %d times\n", (retrytimes+1));
        fd = OpenDev("/dev/ttyUSB2");
        if(fd <= 0) {
            dbg_time("OpenDev Fail!\n");
            CloseDev(fd);
            continue ;
        }

        sleep(1);
        err = UART0_Init(fd,115200,0,8,1,'N');
       // printf("upgrad_check 2 \n");
        if(0 == err) {
            dbg_time("Set Port Exactly!\n");
            CloseDev(fd);
            continue ;
        }
       // printf("upgrad_check 3 \n");
        sleep(1);
        if(!SendATCMD(fd, at_check ,  strlen(at_check) ,  rcv_buf, sizeof(rcv_buf), true)) {
            dbg_time("Send at command failed!\n");
            CloseDev(fd);
            continue ;
        }
        sleep(1);
        memset(rcv_buf, 0, sizeof(rcv_buf));
        if(!SendATCMD(fd, at_cfun, strlen(at_cfun), rcv_buf, sizeof(rcv_buf),true)) {
            dbg_time("read imei failed!\n");
            CloseDev(fd);
            continue ;
        }
        if(NULL==strstr(rcv_buf, "+CFUN: 7")) {
            dbg_time("NV Verify Fail!\n");
            CloseDev(fd);
            continue ;
        } else {
            getcfun=true;
            dbg_time("nv back  ok\n");
            CloseDev(fd);
            break;
        }

    }
    if((!getcfun) && fd > 0){
         CloseDev(fd);
    }
    return getcfun;
}

bool upgrade_ready()
{
    int fd=0;                            //文件描述符
    int err=0;                           //返回调用函数的状态
    char rcv_buf[1024]= {0};
    bool bUpdateDirect=false;
    const char *at_cmd = "at\r\n";
    const char *at_sgsw = "at+sgsw\r\n";
    const char *at_nvcheck = "at+nvburs=2\r\n";
    const char *at_nvback = "at+nvburs=0\r\n";
    /*[zhaopf@meigsmart-2020-0618]when reboot failed, retry { */
   // const char *at_gofastboot_retry = "at+syscmd=sys_reboot bootloader\r\n";
   // const char *at_gofastboot = "at+gofastboot\r\n";
    /*[zhaopf@meigsmart-2020-0618]when reboot failed, retry } */
	
    #if 0
    if(Add_OptionDriver()) {
        write_log("[%d/%d]: Insmod option driver Success!\n", upgrade_step++, upgrade_full_steps);
    } else {
        write_log("[%d/%d] Insmod option driver fail,please check!\n", upgrade_step++, upgrade_full_steps);

        return 0;
    }

    #endif 

   // printf("start detect meig device\n");
	/*[zhaopf@meigsmart-2020-06-22]if in fastboot  mode, need reboot to normal mode to back nv {*/
    #if 0
    if(check_fastboot()){
	    /*[zhaopf@meigsmart]add for Android support { */
       //system(FASTBOOT_EXE" reboot");//reboot to normal mode, as need to backup nv
		/*[zhaopf@meigsmart]add for Android support } */
        printf("alread fastboot mode we think nv have bakup just return!\n");
        return 1;
    }
    #endif
	/*[zhaopf@meigsmart-2020-06-22]if in fastboot  mode, need reboot to normal mode to back nv }*/
    while(get_modem_info(&curr_modem_info) <= 0) {

        printf("---> wait meig usb devices \n");
        if(curr_modem_info.if_name != NULL) {
            free(curr_modem_info.if_name);
            curr_modem_info.if_name = NULL;
        }

        if(curr_modem_info.at_port_name != NULL) {
            free(curr_modem_info.at_port_name);
            curr_modem_info.at_port_name = NULL;
        }

        if(curr_modem_info.modem_port_name != NULL) {
            free(curr_modem_info.modem_port_name);
            curr_modem_info.modem_port_name = NULL;
        }


        sleep(2);
        continue;
    }

    fd = OpenDev(curr_modem_info.at_port_name); //打开串口，返回文件描述符   argv[1]
	/*[zhaopf@meigsmart-2020-06-22]if in fastboot  mode, need reboot to normal mode to back nv {*/
    if(fd <= 0) { //fastboot or other state
        dbg_time("at port open failed,please check!\n");    
        return 0;
    }
	/*[zhaopf@meigsmart-2020-06-22]if in fastboot  mode, need reboot to normal mode to back nv }*/
    if(!bUpdateDirect) {
        err = UART0_Init(fd,115200,0,8,1,'N');
        if(0 == err) {
            dbg_time("Set Port Exactly!\n");
           // write_log("Set Port Exactly!\n");
            CloseDev(fd);

            return 0;
        }
        sleep(1);
        if(!SendATCMD(fd, at_cmd, strlen(at_cmd),rcv_buf,sizeof(rcv_buf),true)) {
            dbg_time("Send at command failed,please check!\n");
            CloseDev(fd);

            return 0;
        } else {
            dbg_time(" Send at command Success!\n");


        }
        sleep(1);
        memset(rcv_buf,0,sizeof(rcv_buf));
        if(!SendATCMD(fd, at_sgsw, strlen(at_sgsw),rcv_buf,sizeof(rcv_buf),true)) {
            dbg_time(" Send at+sgsw command failed,please check!\n");
            CloseDev(fd);
            return 0;
        } else {
            dbg_time("the module version before update is:%s\n",rcv_buf);
            //printf("Send at+sgsw command Success!\n");
           //write_log("the module version before update is:%s\n",rcv_buf);
        }
        sleep(1);
        memset(rcv_buf,0,sizeof(rcv_buf));
        if(!SendATCMD(fd,at_nvcheck, strlen(at_nvcheck), rcv_buf, sizeof(rcv_buf), true)) {
            dbg_time("Send at+nvburs=2 command failed,please check!\n");
            CloseDev(fd);

            return 0;
        }
        sleep(1);
        if(NULL==strstr(rcv_buf,"InnerVersion")) {
            if(!SendATCMD(fd,at_nvback, strlen(at_nvback), rcv_buf, sizeof(rcv_buf), true)) {
                dbg_time("Send at+nvburs=0 command failed,please check!\n");
                CloseDev(fd);

                return 0;
            } else {
                dbg_time(" Backup NV Success!\n");
            }

        }
        memset(rcv_buf,0,sizeof(rcv_buf));
        #if 0
        if(!SendATCMD(fd,at_gofastboot, strlen(at_gofastboot), rcv_buf, sizeof(rcv_buf), false)) {
        /*[zhaopf@meigsmart-2020-0618]when reboot failed, retry { */		
		    if(!SendATCMD(fd,at_gofastboot_retry, strlen(at_gofastboot_retry), rcv_buf, sizeof(rcv_buf), false)) {
                printf("Send at+syscmd=sys_reboot bootloader command failed!\n");
                write_log("Send at+syscmd=sys_reboot bootloader command failed!\n");
                CloseDev(fd);
                return 0;
			}
        /*[zhaopf@meigsmart-2020-0618]when reboot failed, retry } */
            CloseDev(fd);
            return 0;
        } else {
            write_log("Switch to fastboot mode Success!\n");
        }
       // CloseDev(fd);
       
        sleep(6);
        #endif
    }
    CloseDev(fd);
    return 1;
}

void upgrade_reload()
{
    int fd = -1;
    char rcv_buf[1024]= {0};
    const char *at_sgsw= "at+sgsw\r\n";
    const char *at_reboot = "at+syscmd=sys_reboot reboot\r\n";
     fd = OpenDev(curr_modem_info.at_port_name);
     if(fd <= 0) {
            dbg_time("OpenDev Fail!\n");
            CloseDev(fd);
            return;
      }

   if(!SendATCMD(fd,at_sgsw,strlen(at_sgsw), rcv_buf, sizeof(rcv_buf),true)) {
        dbg_time("[upgrade_reload]Send at+sgsw command failed,please check!\n");
        CloseDev(fd);
        return;
    } else {
        dbg_time("[The module version after update is\n");
    }
    sleep(0.5);
    memset(rcv_buf,0,sizeof(rcv_buf));
    if(!SendATCMD(fd,at_reboot, strlen(at_reboot), rcv_buf, sizeof(rcv_buf), false)) {
        dbg_time("Send at+sys_reboot command failed!\n");

    } else {
      dbg_time(" Reloading module......\n");
    }
    CloseDev(fd);
}
/*zqy add support at operation 20210319 end*/
#endif 
static void usage(int status, const char *program_name)
{
    if(status != EXIT_SUCCESS)
    {
        printf("Try '%s --help' for more information.\n", program_name);
    }
    else
    {
        dbg_time("Upgrade Meig's modules with Qualcomm's firehose protocol.\n");
        dbg_time("Usage: %s [options...]\n", program_name);
        dbg_time("    -f [package_dir]               Upgrade package directory path\n");
        dbg_time("    -p [/dev/ttyUSBx]              Diagnose port, will auto-detect if not specified\n");
        dbg_time("    -s [/sys/bus/usb/devices/xx]   When multiple modules exist on the board, use -s specify which module you want to upgrade\n");
        dbg_time("    -e                             Erase All Before Download (will Erase calibration data, careful to USE)\n");
        dbg_time("    -l [dir_name]                  Sync log into a file(will create qfirehose_timestamp.log)\n");

    }
    exit(status);
}

/*
1. enum dir, fix up dirhose_dir
2. md5 examine
3. furture
*/
static int system_ready(char** dirhose_dir)
{
    char temp[255+2];

    if(strstr(*dirhose_dir, "/update/firehose") != NULL)
    {
    }else
    {
        //set_transfer_allbytes(calc_filesizes(*dirhose_dir));
        sprintf(temp, "%s/update/firehose", *dirhose_dir);
        if(access(temp, R_OK))
            error_return();
        free(*dirhose_dir);
        *dirhose_dir = strdup(temp);
        return 0;
    }
    error_return();
}

static int detect_and_judge_module_version(void *usb_handle) {
    static uint8_t version[64] = {'\0'};

    if (usb_handle && version[0] == '\0') {
        retrieve_soft_revision(usb_handle, version, sizeof(version));
        if (version[0]) {
            size_t i = 0;
            size_t length = strlen((const char *)version) - strlen("R00A00");
            dbg_time("old software version: %s\n", version);
            for (i = 0; i < length; i++) {
                if (version[i] == 'R' && isdigit(version[i+1]) &&  isdigit(version[i+2])
                    && version[i+3] == 'A'  && isdigit(version[i+4]) &&  isdigit(version[i+5]))
                {
                    version[i] = '\0';
                    //dbg_time("old hardware version: %s\n", mobile_software_revision);
                    break;
                }
            }
        }
    }
        
    if (version[0])
        return 0;
    
    error_return();
}
int  debug_mode = 0;
FILE* loghandler = NULL;
#ifdef FIREHOSE_ENABLE
int firehose_main_entry(int argc, char* argv[])
#else
int main(int argc, char* argv[])
#endif
{
    int opt;
    int check_hash = 1;
    int retval;
    void *usb_handle = NULL;
    int idVendor = 0, idProduct = 0, interfaceNum = 0;
    int edl_retry = 30; //SDX55 require long time by now 20190412
    double start;
    char *firehose_dir = malloc(MAX_PATH);
    char *module_port_name = malloc(MAX_PATH);
    char *module_sys_path = malloc(MAX_PATH);
    int xhci_usb3_to_usb2_cause_syspatch_chage = 1;
    int usb2tcp_port = 0;
    char filename[128] = {'\0'};
	const char *usbmon_logfile = NULL;

    firehose_dir[0] = module_port_name[0] = module_sys_path[0] = '\0';

    /* set file priviledge mask 0 */
    umask(0);
    /*build V1.0.8*/
    dbg_time("Firehose Version: Meig_Firehose_Linux&Android_V1.3\n"); //when release, rename to V1.X
#ifndef __clang__
    dbg_time("Builded: %s %s\n", __DATE__,__TIME__);
#endif

#ifdef ANDROID
    struct passwd* passwd;
    passwd = getpwuid(getuid());
    dbg_time("------------------\n");
    dbg_time("User:\t %s\n",passwd->pw_name);
    struct group* group;
    group = getgrgid(passwd->pw_gid);
    dbg_time("Group:\t %s\n", group->gr_name);
    dbg_time("------------------\n");
#if 0 //not all customers need this function
    loghandler = fopen("/data/upgrade.log", "w+");
#endif
    if (loghandler) dbg_time("upgrade log will be sync to /data/upgrade.log\n");
#endif

    optind = 1;
    while ( -1 != (opt = getopt(argc, argv, "f:p:z:s:l:u:nedh"))) {
        switch (opt) {
            case 'n':
                check_hash = 0;
                break;
            case 'l':
                if (loghandler) fclose(loghandler);
                snprintf(filename, sizeof(filename), "%s/meigfirehose_%lu.log", optarg, time(NULL));
                dbg_time("upgrade log file is:%s",filename);
                sleep(10);
                loghandler = fopen(filename, "w+");
                if (loghandler) dbg_time("upgrade log will be sync to %s\n", filename);
                break;
            case 'f':
                strncpy(firehose_dir, optarg, MAX_PATH);
            break;
            case 'p':
                strncpy(module_port_name, optarg, MAX_PATH);
                if (!strcmp(module_port_name, "9008")) {
                    usb2tcp_port = atoi(module_port_name);
                    module_port_name[0] = '\0';
                }
            break;
            case 's':
                xhci_usb3_to_usb2_cause_syspatch_chage = 0;
                strncpy(module_sys_path, optarg, MAX_PATH);
                if (module_sys_path[strlen(optarg)-1] == '/')
                    module_sys_path[strlen(optarg)-1] = '\0';
                break;
            case 'z':
                qusb_zlp_mode = !!atoi(optarg);
                dbg_time("qusb_zlp_mode is:%d",qusb_zlp_mode);
                break;
            case 'e':    
                q_erase_all_before_download = 1;
                break;
	    case 'u':
		usbmon_logfile = strdup(optarg);
                break;
            case 'd':
                debug_mode = 1;
                break;
            case 'h':
                usage(EXIT_SUCCESS, argv[0]);
                break;
            default:
            break;
        }
    }

    if (usbmon_logfile)
        ql_capture_usbmon_log(usbmon_logfile);

    update_transfer_bytes(0);
    if (usb2tcp_port)
        goto _usb2tcp_start;

    if (firehose_dir[0] == '\0') {
        usage(EXIT_SUCCESS, argv[0]);
        update_transfer_bytes(-1);
        error_return();
    }
        
    if (access(firehose_dir, R_OK)) {
        dbg_time("fail to access %s, errno: %d (%s)\n", firehose_dir, errno, strerror(errno));
        update_transfer_bytes(-1);
        error_return();
    }

    opt = strlen(firehose_dir);
    if (firehose_dir[opt-1] == '/') {
        firehose_dir[opt-1] = '\0';
    }
    
    if (!g_part_upgrade) {
        struct stat st;
        const char *update_dir = "/update/";
        char *update_pos = strstr(firehose_dir, update_dir);

        if (update_pos && lstat(firehose_dir, &st) == 0 && S_ISDIR(st.st_mode) == 0) {
            *update_pos = '\0';            

            g_part_upgrade = strdup(update_pos + strlen(update_dir));
        }
    }
    #if 0
    // check the md5 value of the upgrade file
    if (check_hash && !g_part_upgrade && md5_check(firehose_dir)) {
        update_transfer_bytes(-1);
        error_return();
    }
    #endif
    //zqy add not support md5
    #if 0
    if(system_ready(&firehose_dir)) {
        update_transfer_bytes(-1);
        error_return();
    }
    #endif
    if(!upgrade_ready()){
       update_transfer_bytes(-1);
       dbg_time("nvback fail return");
       error_return();
    } 

    //zay add not support md5
   // dbg_time("0-0 module sys path is:%s",module_sys_path);
    if (module_port_name[0] && !strncmp(module_port_name, "/dev/mhi", strlen("/dev/mhi"))) {
        if (qpcie_open(firehose_dir)) {
            update_transfer_bytes(-1);
            error_return();
        }      
		
        usb_handle = &edl_pcie_mhifd;
        start = get_now();
        goto __firehose_main;
    }
    else if (module_port_name[0] && strstr(module_port_name, ":9008")) {
        strcpy(module_sys_path, module_port_name);
        goto __edl_retry;
    }

_usb2tcp_start:
   // dbg_time("0-1 module sys path is:%s",module_sys_path);
    if (module_sys_path[0] && access(module_sys_path, R_OK)) {
        dbg_time("fail to access %s, errno: %d (%s)\n", module_sys_path, errno, strerror(errno));
        update_transfer_bytes(-1);
        error_return();
    }
   // dbg_time("0-2 module sys path is:%s",module_sys_path);
    if (module_port_name[0] && access(module_port_name, R_OK | W_OK)) {
        dbg_time("fail to access %s, errno: %d (%s)\n", module_port_name, errno, strerror(errno));
        update_transfer_bytes(-1);
        error_return();
    }
   // dbg_time("0-3 module sys path is:%s",module_sys_path);
    if (module_sys_path[0] == '\0' && module_port_name[0] != '\0') {
        //get sys path by port name
        meig_get_syspath_name_by_ttyport(module_port_name, module_sys_path, MAX_PATH);
    }
   // dbg_time("1 module_sys_path is*****************:%s*****************************",module_sys_path);
    if (module_sys_path[0] == '\0') {
       // dbg_time("run this to get module_sys_path");
        int module_count = auto_find_meig_modules(module_sys_path, MAX_PATH);
       // dbg_time("after this module sys path is:%s",module_sys_path);
        if (module_count <= 0) {
            dbg_time("Meig module not found\n");
            update_transfer_bytes(-1);
            error_return();
        }
        else if (module_count == 1) {

        } else {
            dbg_time("There are multiple meig modules in system, Please use <-s /sys/bus/usb/devices/xx> specify which module you want to upgrade!\n");
            dbg_time("The module's </sys/bus/usb/devices/xx> path was printed in the previous log!\n");
            update_transfer_bytes(-1);
            error_return();
        }
    }
   // dbg_time("2 module_sys_patch is ********************************%s********************",module_sys_path);
__edl_retry:
    while (edl_retry-- > 0) {
        usb_handle = qusb_noblock_open(module_sys_path, &idVendor, &idProduct, &interfaceNum);
  //      if(usb_handle != NULL){
//            dbg_time("meig usb interface intr_ep is%d,bulk_ep in is%d,bulk_ep out is%d",((*meig_usb_device)usb_handle)->intr_ep[0],((*meig_usb_device)usb_handle)->bulk_ep_in[0],((*meig_usb_device)usb_handle)->bulk_ep_out[0]);

 //       }
        if (usb_handle == NULL && module_sys_path[0] == '/') {
            sleep(1); //in reset sate, wait connect
            if (xhci_usb3_to_usb2_cause_syspatch_chage && access(module_sys_path, R_OK) && errno_nodev()) {
                auto_find_meig_modules(module_sys_path, MAX_PATH);
            }
            else if (access(module_sys_path, R_OK) && errno_nodev()) {
                int busidx = strlen("/sys/bus/usb/devices/");
                char busnum = module_sys_path[busidx];

                module_sys_path[busidx] = busnum-1;
                if (access(module_sys_path, R_OK) && errno_nodev())
                    module_sys_path[busidx] = busnum+1;

                if (!access(module_sys_path, R_OK)) {
                    usb_handle = qusb_noblock_open(module_sys_path, &idVendor, &idProduct, &interfaceNum);
                    if (usb_handle && (idVendor != 0x05c6 || idProduct != 0x9008)) {
                        qusb_noblock_close(usb_handle);
                        usb_handle = NULL;  
                    }
                }
                module_sys_path[busidx] = busnum;
            }

            if (usb_handle == NULL)
                continue;
        }

        if ((idVendor == 0x2dee ||idVendor == 0x05c6) && interfaceNum > 1) {
            if (detect_and_judge_module_version(usb_handle)) {
                // update_transfer_bytes(-1);
                /* do not return here, this command will fail when modem is not ready */
                // error_return();
            }
        }

        if (interfaceNum == 1) {
            if ((idVendor == 0x4D22) && (idProduct == 0x0800)) {
                // although 5G module stay in dump mode, after send edl command, it also can enter edl mode
                dbg_time("5G module stay in dump mode!\n");				
            } else {
                dbg_time("test this happen in edl mode");
               // sleep(20);
   //            dbg_time("meig usb interface intr_ep is%d,bulk_ep in is%d,bulk_ep out is%d",((*meig_usb_device)usb_handle)->intr_ep[0],((*meig_usb_device)usb_handle)->bulk_ep_in[0],((*meig_usb_device)usb_handle)->bulk_ep_out[0]);
                break;					
            }
            dbg_time("something went wrong???, why only one interface left\n");
        }

        switch_to_edl_mode(usb_handle);
        qusb_noblock_close(usb_handle);
        usb_handle = NULL;
        sleep(1); //wait usb disconnect and re-connect
    }

    if (usb_handle == NULL) {
        update_transfer_bytes(-1);
        error_return();
    }

    if (usb2tcp_port) {
        retval = usb2tcp_main(usb_handle, usb2tcp_port, qusb_zlp_mode);
        qusb_noblock_close(usb_handle);
        return retval;
    }

    start = get_now();
    retval = sahara_main(firehose_dir, usb_handle, idVendor == 0x05c6);

    if (!retval) {
        if (idVendor != 0x05C6) {
            sleep(1);
            stream_download(firehose_dir, usb_handle, qusb_zlp_mode);
            qusb_noblock_close(usb_handle);
            sleep(1);
            goto __edl_retry;
        }

__firehose_main:
        retval = firehose_main(firehose_dir, usb_handle, qusb_zlp_mode);
        if(retval == 0)
        {
            get_duration(start);
        }
    }
    #if 1
    /*zqy add 20210319 support at operation start*/

    fprintf(stdout,"upgrade image %s.\n", retval == 0 ? "finished":"some error happen in upgrade image"); 
    
    sleep(10);
    fprintf(stdout,"module restart wait port ok");
        
    while(get_modem_info(&curr_modem_info) <= 0) {

        printf("---> wait meig usb devices \n");
        if(curr_modem_info.if_name != NULL) {
            free(curr_modem_info.if_name);
            curr_modem_info.if_name = NULL;
        }

        if(curr_modem_info.at_port_name != NULL) {
            free(curr_modem_info.at_port_name);
            curr_modem_info.at_port_name = NULL;
        }

        if(curr_modem_info.modem_port_name != NULL) {
            free(curr_modem_info.modem_port_name);
            curr_modem_info.modem_port_name = NULL;
        }


        sleep(2);
        continue;
    }
     
    /*zqy add 20210319 support at operation end*/
    #if 1    
    if(upgrade_check()) {
        dbg_time(" Upgrade check imei ok \n");
    } else {
        dbg_time("Upgrade check imei failed!!!\n");
        retval = 0;
    }
    #endif
    #if 0
    if(upgrade_check_cfun()){
        dbg_time(" Upgrade check nv back up ok \n");
    }else {
        dbg_time(" Upgrade check nv back up failed \n");
        retval = 0;
    }
    #endif 
    fprintf(stdout,"nv backup success module restart please wait for a few seconds\n");
    sleep(8);
    #endif
    upgrade_reload();
    qusb_noblock_close(usb_handle);

    if (firehose_dir) free(firehose_dir);
    if (module_port_name) free(module_port_name);
    if (module_sys_path) free(module_sys_path);
    if (g_part_upgrade) free((char *)g_part_upgrade);

    dbg_time("Upgrade module %s.\n", retval == 0 ? "successfully" : "failed");
   // fprintf(stdout,"Upgrade module %s.\n",retval == 0 ? "successfully":"failed");
    if (loghandler) fclose(loghandler);
    if (retval) update_transfer_bytes(-1);
	if (usbmon_logfile) ql_stop_usbmon_log();
	
    return retval;
}

double get_now()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

void get_duration(double start)
{
   // dbg_time("THE TOTAL DOWNLOAD TIME IS %.3f s\n",(get_now() - start));
      fprintf(stdout,"The total download time is %.3f s\n",(get_now() -start));
}

void set_transfer_allbytes(long long bytes)
{
    transfer_bytes = 0;
    all_bytes_to_transfer = bytes;
}

int update_progress_msg(int percent);
int update_progress_file(int percent);
/*
return percent
*/
int update_transfer_bytes(long long bytes_cur)
{
    static int last_percent = -1;
    int percent = 0;

    if (bytes_cur == -1 || bytes_cur == 0)
    {
        percent = bytes_cur;
    }
    else
    {
        transfer_bytes += bytes_cur;
        percent = (transfer_bytes * 100) / all_bytes_to_transfer;
    }

    if (percent != last_percent)
    {
        last_percent = percent;
#ifdef USE_IPC_FILE
          
       // update_progress_file(percent);
#endif
#ifdef USE_IPC_MSG
       //  update_progress_msg(percent);
#endif
    }

    return percent;
}

void show_progress()
{
    static int percent = 0;

    if (all_bytes_to_transfer)
        percent = (transfer_bytes * 100) / all_bytes_to_transfer;
    dbg_time("upgrade progress %d%% %lld/%lld\n", percent, transfer_bytes, all_bytes_to_transfer);
    fprintf(stdout,"upgrade progress %d%% %lld/%lld\n",percent,transfer_bytes,all_bytes_to_transfer);
}

#ifdef USE_IPC_FILE
#define IPC_FILE_ANDROID "/data/update.conf"
#define IPC_FILE_LINUX "/tmp/update.conf"
int update_progress_file(int percent)
{
    static int ipcfd = -1;
    char buff[16];

    if (ipcfd < 0)
    {
#ifdef ANDROID
        const char *ipc_file = IPC_FILE_ANDROID;
#else
        const char *ipc_file = IPC_FILE_LINUX;
#endif
        /* Have set umask previous, no need to call fchmod */
        ipcfd = open(ipc_file, O_TRUNC | O_CREAT | O_WRONLY | O_NONBLOCK, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if (ipcfd < 0)
        {
            dbg_time("Fail to open(O_WRONLY) %s: %s\n", ipc_file, strerror(errno));
            return -1;
        }
    }

    lseek(ipcfd, 0, SEEK_SET);
    snprintf(buff, sizeof(buff), "%d", percent);
    if (write(ipcfd, buff, strlen(buff)) < 0)
        dbg_time("fail to write upgrade progress into %s: %s\n", ipc_file, strerror(errno));

    if (percent == 100 || percent < 0)
        close(ipcfd);
    return 0;
}
#endif

#ifdef USE_IPC_MSG
#define MSGBUFFSZ 16
struct message
{
    long mtype;
    char mtext[MSGBUFFSZ];
};

#define MSG_FILE "/etc/passwd"
#define MSG_TYPE_IPC 1
static int msg_get()
{
    key_t key = ftok(MSG_FILE, 'a');
    int msgid = msgget(key, IPC_CREAT | 0644);

    if (msgid < 0)
    {
        dbg_time("msgget fail: key %d, %s\n", key, strerror(errno));
        return -1;
    }
    return msgid;
}

static int msg_rm(int msgid)
{
    return msgctl(msgid, IPC_RMID, 0);
}

static int msg_send(int msgid, long type, const char *msg)
{
    struct message info;
    info.mtype = type;
    snprintf(info.mtext, MSGBUFFSZ, "%s", msg);
    if (msgsnd(msgid, (void *)&info, MSGBUFFSZ, IPC_NOWAIT) < 0)
    {
        dbg_time("msgsnd faild: msg %s, %s\n", msg, strerror(errno));
        return -1;
    }
    return 0;
}

static int msg_recv(int msgid, struct message *info)
{
    if (msgrcv(msgid, (void *)info, MSGBUFFSZ, info->mtype, IPC_NOWAIT) < 0)
    {
        dbg_time("msgrcv faild: type %ld, %s\n", info->mtype, strerror(errno));
        return -1;
    }
    return 0;
}

/**
 * this function will not delete the msg queue
 */
int update_progress_msg(int percent)
{
    char buff[MSGBUFFSZ];
    int msgid = msg_get();
    if (msgid < 0)
        return -1;
    snprintf(buff, sizeof(buff), "%d", percent);

#ifndef IPC_TEST
    return msg_send(msgid, MSG_TYPE_IPC, buff);
#else
    msg_send(msgid, MSG_TYPE_IPC, buff);
    struct message info;
    info.mtype = MSG_TYPE_IPC;
    msg_recv(msgid, &info);
    printf("msg queue read: %s\n", info.mtext);
#endif
}
#endif
