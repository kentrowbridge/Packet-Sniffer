#include <iostream>
#include <tins/tins.h>
#include <time.h>
//#include <unordered_map>

using namespace Tins;
/////////////////////////////////
//Author: Kenny Trowbridge
//Last Modified: 4/11
/////////////////////////////////

//method declarations
bool processPacket(const PDU &pdu);

//variables
time_t start;
//unordered_map<IPv4Address, int> srcTable;
//unordered_map<IPv4Address, int> destTable;

//structures
struct tally{
	int count;
	IPv4Address ipDest;
};

int main(){
	//set the start time of program
	start = time(NULL);

	//create configuration for sniffer
	SnifferConfiguration config;
	//set it to promiscuous mode
	config.set_promisc_mode(true);

	//create the packet sniffer to listen on wireless port
	Sniffer sniffer("wlan0", config);

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

	//if src not seen already, add it
	//otherwise increment that src address' count
	// if (srcTable.count(ip.src_addr() == 0){
	// 	srcTable.emplace(ip.src_addr(), 1);
	// }
	// else {
	// 	srcTable[ip.src_addr()] += 1;
	// }

	//if dest not seen already, add it
	//otherwise increment that dest address' count
	// if (destTable.count(ip.src_addr() == 0){
	// 	destTable.emplace(ip.src_addr(), 1);
	// }
	// else {
	// 	destTable[ip.dest_addr()] += 1;
	// }

	//continue
	return true;
}