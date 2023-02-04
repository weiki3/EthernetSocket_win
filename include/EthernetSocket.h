#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <pcap.h>

#define uint8_t unsigned char
#define uint16_t unsigned short int
#define ETH_ALEN 6

// EtherSock 句柄
struct EtherSockWin
{
	int protocol; // 传输协议
	pcap_t* fp; // 网卡句柄
	uint8_t localMacAddr[6]; // 网卡mac地址
	struct bpf_program* fcode; // 设置过滤规则
};

struct ether_header
{
	uint8_t ether_dhost[ETH_ALEN];      // destination eth addr 
	uint8_t ether_shost[ETH_ALEN];      // source ether addr    
	uint16_t ether_type;                 // packet type ID field 
};

typedef struct EtherSockWin EtherSock;

// 创建EthernetSocket
// 不需要转换 protocol 的字节序
// 需要额外提供网卡的 mac 地址
EtherSockWin* createEthernetSocket(const char* networkCardName, int protocol, const uint8_t* localMacAddress);

// 释放EthernetSocket
void freeEthernetSocket(EtherSockWin* etherSock);

// 数据链路层发送函数接口
// 成功传输返回0,失败返回1
// 包的长度不大于1500且不小于0
int sendOverEthernet(const EtherSockWin* etherSock, const uint8_t* destMacAddress, const uint8_t* packetData, int packetDataLen);

// 数据链路层接受函数接口
// 成功返回实际接收到的 packet 长度, 失败返回 -1
int recvOverEthernet(const EtherSockWin* etherSock, uint8_t* packetBuffer, int packetLen);

// 初始化用于接收的EtherSock
// 设置过滤规则, 成功返回 0，失败返回 1 
int initRecvEthernetSocket(EtherSockWin* etherSock);

// 设置dll位置
int LoadNpcapDlls();

// 处理接收到的帧
void frame_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

// 查看unsigned char数组
void ShowData(unsigned char* d1, int len);

// 将unsigned int整数转化为hex字符串
void itox(unsigned int i, char* s);