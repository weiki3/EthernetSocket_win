#include <EthernetSocket.h>

int LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}

EtherSockWin* createEthernetSocket(const char* networkCardName, int protocol, const uint8_t* localMacAddress)
{
	pcap_t* fp = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	if ((fp = pcap_open(networkCardName, 65536, 0, 1000, NULL, errbuf)) == NULL)
	{
		printf("ERROR: %s\n", errbuf);
		printf("Failed to create pcap, please check the network card name\n");
		return NULL;
	}
	EtherSock* etherSock = (EtherSock*)malloc(sizeof(EtherSock));
	if (!etherSock)
	{
		printf("Failed to malloc\n");
		return NULL;
	}

	etherSock->fp = fp;
	etherSock->protocol = protocol;
	etherSock->fcode = NULL;
	memcpy(etherSock->localMacAddr, localMacAddress, 6 * sizeof(uint8_t));

	return etherSock;
}

void freeEthernetSocket(EtherSockWin* etherSock)
{
	pcap_close(etherSock->fp);
	free(etherSock);
}
int sendOverEthernet(const EtherSockWin* etherSock, const uint8_t* destMacAddress, const uint8_t* packetData, int packetDataLen)
{
	if (packetDataLen > 1500 || packetDataLen < 0)
	{
		perror("Invalid input of packetDataLen\n");
		exit(EXIT_FAILURE);
	}

	// 创建 Ethernet II 帧头
	struct ether_header header;

	// 创建缓冲区
	int bufferSize = sizeof(struct ether_header) + packetDataLen;
	uint8_t* buffer = (uint8_t*)malloc(bufferSize);
	if (!buffer)
	{
		printf("Failed to malloc\n");
		return -1;
	}

	// MAC地址拷贝
	memcpy(header.ether_dhost, destMacAddress, 6);
	memcpy(header.ether_shost, etherSock->localMacAddr, 6);

	// 拷贝协议
	header.ether_type = etherSock->protocol;

	memcpy(buffer, &header, sizeof(header));
	memcpy(buffer + sizeof(header), packetData, packetDataLen);

	// 发送数据
	if (pcap_sendpacket(etherSock->fp, buffer, bufferSize) != 0)
	{
		perror("Failed to send by pcap\n");
		return 1;
	}
	return 0;
}

int recvOverEthernet(const EtherSockWin* etherSock, uint8_t* packetBuffer, int packetLen)
{
	if (packetLen > 1500 || packetLen < 0)
	{
		perror("Invalid input of packetLen\n");
		return -1;
	}

	uint8_t* tempParam = (uint8_t*)malloc(packetLen + 2);
	if (!tempParam)
	{
		printf("Failed to malloc\n");
		return -1;
	}
	memset(tempParam, 0, packetLen + 2);

	// 存放需要的数据包长度，处理长度小于46的情况
	tempParam[0] = packetLen / 0x100;
	tempParam[1] = packetLen % 0x100;

	if (pcap_loop(etherSock->fp, 1, frame_handler, tempParam))
		return -1;

	memcpy(packetBuffer, tempParam + 2, packetLen);
	packetLen = tempParam[0] * 0x100 + tempParam[1]; // packetLen被借用来表示实际接收到的数据包大小
	free(tempParam);

	return packetLen;
}

void frame_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	int packetLen = param[0] * 0x100 + param[1]; // 规定的数据包长度
	packetLen = packetLen < header->caplen - 14 ? packetLen : header->caplen - 14;

	if (header->caplen >= 14)
		memcpy(param + 2, pkt_data + 14, packetLen);
	else
		return;
	// 储存实际接收数据包大小
	param[0] = (packetLen) / 0x100;
	param[1] = (packetLen) % 0x100;
}

int initRecvEthernetSocket(EtherSockWin* etherSock)
{
	//检查数据链路层,只考虑以太网
	if (pcap_datalink(etherSock->fp) != DLT_EN10MB) {
		printf("This program works only on Ethernet networks\n");
		return 1;
	}

	etherSock->fcode = (struct bpf_program*)malloc(sizeof(struct bpf_program));
	if (!etherSock->fcode)
	{
		printf("Failed to malloc\n");
		return 1;
	}

	char filterString[19] = "ether proto 0x";
	itox(etherSock->protocol, filterString + 14);

	if (pcap_compile(etherSock->fp, etherSock->fcode, filterString, 1, PCAP_NETMASK_UNKNOWN) < 0)
	{
		printf("Failed to compile frame filter\n");
		return 1;
	}

	if (pcap_setfilter(etherSock->fp, etherSock->fcode) < 0)
	{
		printf("Failed to set frame filter\n");
		return 1;
	}

	return 0;
}

void ShowData(unsigned char* d1, int len)
{
	int i;
	for (i = 0; i < len; i++)
		printf("%02x ", d1[i]);
	printf("\n");
}

void itox(unsigned int i, char* s)
{
	unsigned char n;

	s += 4;
	*s = '\0';

	for (n = 4; n != 0; --n) {
		*--s = "0123456789ABCDEF"[i & 0x0F];
		i >>= 4;
	}
}