#include <iostream>
#include <tins/tins.h>
#include <time.h>
#include "sniffer.h"
#include "linknode.h"

using namespace Tins;
/////////////////////////////////
//Author: Kenny Trowbridge
//Last Modified: 4/20
/////////////////////////////////

time_t start;
//initialize the storage list
LinkNode* head = NULL;

int main(){
	//set the start time of program
	start = time(NULL);

	//create configuration for sniffer
	SnifferConfiguration config;
	//make sniffer look at all packets over 
	config.set_promisc_mode(true);

	//create the packet sniffer to listen on wireless port
	Sniffer sniffer("wlan0", config);

	std::cout << "Sniffing Packets..." << std::endl;
	std::cout << "src -> dst : size" <<std::endl;

	//each packet received will be processed
	sniffer.sniff_loop(processPacket);

	std::cout<<"Finished!"<<std::endl;

	mergeSort(head);

	printList(head);

	return 0;
}

/* processPacket()
 *
 * This method is called on every packet that the sniffloop picks up.
 * When the method returns true, the loop continues and when the method
 * returns false, the loop is ended.  This method only returns false when
 * a specified amount of time has passed.
 *
 */
bool processPacket(const PDU &pdu) {
	//time check, if past 2 minutes, stop looping
	if(difftime(time(NULL), start) >= SNIFF_TIME)return false;

	//retrieve IP information from PDU
	const IP &ip = pdu.rfind_pdu<IP>();

	//determine which IP address is on LAN
	//address of the local address in packet
	IPv4Address local;

	//defining local as any address whose first 8 bits = 10
	AddressRange<IPv4Address> localRange ("10.0.0.1", "10.255.255.255");
	
	//if the src is local, set local to src, else local = dst
	local = localRange.contains(ip.src_addr()) ? ip.src_addr() 
											   : ip.dst_addr();

	//examine list for local address, if it is already there
	//increment count and data size, else create a node for it
	if(!searchList(local, pdu.size(), &head))
	{
		//if it is not found, add it to the tail
		LinkNode* newNode = makeNode(local, pdu.size());

		//insert it at the tail
		insertNode(newNode, &head);
	}

	//print packet src -> dst : size to stdout
	std::cout << ip.src_addr() << "  ->  " 
		<< ip.dst_addr() << " : " << pdu.size()
		<<std::endl;

	//continue
	return true;
}

/* printList()
 *
 * Method takes a linked list and prints out the first 5
 * entries.
 *
 */
void printList(LinkNode* head) {
	int counter = 0;
	//print out the first five entries in the list
	while(head != NULL && counter <= 5)
	{
		std::cout << "====" << head->ip <<"===="<<std::endl;
		std::cout << "	number of packets: " << head->count <<std::endl;
		std::cout << "	total data received/sent: " << head->totalData << std::endl;
		//move to next link
		head = head->next;
		counter++;
	}
}