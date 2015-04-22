#include <iostream>
#include <tins/tins.h>
#include <time.h>
#include <string>
#include "sniffer.h"
#include "linknode.h"

using namespace Tins;
/////////////////////////////////
//Author: Kenny Trowbridge
//Author: Casey Sigelmann
//Author: Matthew Ong
//Last Modified: 4/22/15
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

	printf("Sniffing Packets...\n");
	printf("source -> destination : size\n");

	//each packet received will be processed
	sniffer.sniff_loop(processPacket);

	printf("Finished!\n");

	//sort the list of IPs
	mergeSort(head);

	//print results of sniffing
	printList(&head);

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

	//defining local as any address that starts with 10.
	AddressRange<IPv4Address> localRange ("10.0.0.1", "10.255.255.255");
	
	//if the src is local, add or increment in the list
	local = ip.src_addr();
	if(localRange.contains(local))
	{
		//examine list for local address, if it is already there
		//increment count and data size, else create a node for it
		if(!searchList(local, pdu.size(), &head))
		{
			//if it is not found, add it to the tail
			LinkNode* newNode = makeNode(local, pdu.size());

			//insert it at the tail
			insertNode(newNode, &head);
		}
	}

	//if the dst is local, add or increment in the list
	local = ip.dst_addr();
	if(localRange.contains(local))
	{
		//examine list for local address, if it is already there
		//increment count and data size, else create a node for it
		if(!searchList(local, pdu.size(), &head))
		{
			//if it is not found, add it to the tail
			LinkNode* newNode = makeNode(local, pdu.size());

			//insert it at the tail
			insertNode(newNode, &head);
		}
	}

	//print packet src -> dst : size to stdout
	std::cout << ip.src_addr() << "  ->  " 
		<< ip.dst_addr() << " : " << pdu.size() << "B"
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
void printList(LinkNode** head) {
	if(head == NULL) return;

	LinkNode* iterator = (*head);
	int counter = 0;
	//print out the first five entries in the list
	while(iterator != NULL && counter <= 5)
	{
		std::cout << "==== " << iterator->ip <<" ===="<<std::endl;
		std::cout << "	number of packets: " << iterator->count <<std::endl;
		std::cout << "	total data received/sent: " << iterator->totalData << "B"<< std::endl;
		//move to next link
		iterator = iterator->next;
		counter++;
	}
}