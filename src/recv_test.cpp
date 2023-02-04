#pragma comment(lib, "wpcap.lib")
#include <EthernetSocket.h>

#define ETH_P_DEAN 0x0909
#define ETH_NAME "rpcap://\\Device\\NPF_{EFEF628D-DBA1-4C02-955F-01620A0FFC12}"

const uint8_t local_mac[6] = {0x98, 0x8d, 0x46, 0x18, 0x60, 0x23};

int main()
{
	LoadNpcapDlls();
	const int size = 14;
	uint8_t buffer[size] = {0};
	EtherSock *etherSock = createEthernetSocket(ETH_NAME, ETH_P_DEAN, local_mac);
	if (initRecvEthernetSocket(etherSock))
	{
		printf("Failed when initialize ethersock\n");
		return 1;
	}
	int n;
	if ((n = recvOverEthernet(etherSock, buffer, size)) == -1)
	{
		printf("Failed\n");
		return 1;
	}
	ShowData(buffer, size);
	printf("buffer:%s\n", buffer);
	printf("Capture len:%d\n", n);
	freeEthernetSocket(etherSock);
	return 0;
}