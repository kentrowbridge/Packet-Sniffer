#include <iostream>
#include <tins/tins.h>
#include <time.h>

using namespace Tins;
/////////////////////////////////
//Author: Kenny Trowbridge
//Last Modified: 4/11
/////////////////////////////////

//method declarations
bool processPacket(const PDU &pdu);

//variables
time_t start;

//structures
struct tally{
	int count;
	IPv4Address ipDest;
};

int main(){
	//set the start time of program
	start = time(NULL);

	//create the packet sniffer to listen on wireless port
	Sniffer sniffer("wlan0");

	//each packet received will be processed
	sniffer.sniff_loop(processPacket);

	std::cout<<"Finished!"<<std::endl;
	return 0;
}

//process each packet to calculate network usage
bool processPacket(const PDU &pdu) {
	//time check, if past 2 minutes, stop looping
	if(difftime(time(NULL), start) >= 30)return false;

	//retrieve IP information from PDU
	const IP &ip = pdu.rfind_pdu<IP>();

	//print to stdout
	std::cout << ip.src_addr() << "  ->  " 
		<< ip.dst_addr() << std::endl;

	//continue
	return true;
}