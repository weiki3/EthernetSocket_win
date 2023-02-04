#pragma comment(lib, "wpcap.lib")
#include <EthernetSocket.h>

#define ETH_P_DEAN 0x0909
#define ETH_NAME "rpcap://\\Device\\NPF_{EFEF628D-DBA1-4C02-955F-01620A0FFC12}"

const uint8_t local_mac[6] = {0x98, 0x8d, 0x46, 0x18, 0x60, 0x23};
const uint8_t board_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

int main()
{
	LoadNpcapDlls();
	uint8_t hello[14] = "hello world!\n";
	EtherSock *etherSock = createEthernetSocket(ETH_NAME, ETH_P_DEAN, local_mac);
	if (sendOverEthernet(etherSock, board_mac, hello, 12))
	{
		printf("Failed\n");
		return 1;
	}
	freeEthernetSocket(etherSock);
	printf("Send Packet on 0x0909: hello world!\n");
	system("pause");
}