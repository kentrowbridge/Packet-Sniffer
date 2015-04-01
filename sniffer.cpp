#include <iostream>
#include <tins/tins.h>

using namespace Tins;

struct {
	int count;
	IPv4Address ipDest;
};

int main(){



	SnifferConfiguration config;
	config.set_promisc_mode(true);

	Sniffer sniffer("wlan0", config);

	PDU *packet = sniffer.next_packet();

	std::cout<<"Found packet: "<<(*packet).pdu_type()<<std::endl;

	delete packet;

	std::cout<<"Finished!"<<std::endl;

	return 0;
}