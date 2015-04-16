#include <iostream>
#include <tins/tins.h>
#include <time.h>
//#include "packetSniff.h"
//#include <unordered_map>

using namespace Tins;
/////////////////////////////////
//Author: Kenny Trowbridge
//Last Modified: 4/11
/////////////////////////////////

//structures
typedef struct linkNodeTag {
	int count;
	int totalData;
	IPv4Address ip;
	linkNodeTag * next;
} linkNode;

//method declarations
bool processPacket(const PDU &pdu);
linkNode* makeNode(IPv4Address addr, int size);



//variables
time_t start;
//initialize the storage list
linkNode* head = NULL;

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

	//each packet received will be processed
	sniffer.sniff_loop(processPacket);

	std::cout<<"Finished!"<<std::endl;
	return 0;
}

//process each packet to calculate network usage
bool processPacket(const PDU &pdu) {
	//time check, if past 2 minutes, stop looping
	if(difftime(time(NULL), start) >= 120)return false;

	//create a raw pdu to retrieve data for pay load size
	const RawPDU &raw = pdu.rfind_pdu<RawPDU>();

	//retrieve IP information from PDU
	const IP &ip = pdu.rfind_pdu<IP>();

	//determine which IP address is on LAN
	//address of the local address in packet
	IPv4Address local;

	//defining local as any address whose first 8 bits = 10
	AddressRange<IPv4Address> localRange = IPv4Address("10.0.0.1") / 8;
	
	//if the src is local, set local to src, else local = dst
	local = localRange.contains(ip.src_addr()) ? ip.src_addr() 
											: ip.dst_addr();

	//examine list for local address, if it is already there
	//increment count and data size, else create a node for it
	//INPROGRESS

	//print to stdout
	std::cout << ip.src_addr() << "  ->  " 
		<< ip.dst_addr() << " : " << raw.payload_size()
		<<std::endl;

	//continue
	return true;
}

//search the storage list for this ip node
bool searchList(const IPv4Address addr) {

	linkNode* iterator = head;
	while(iterator != NULL)
	{//if this ip address is in the list return true
		if(iterator->ip == addr) 
		{	
			//increment count on this node
			iterator->count++;
			return true;
		}
	}
	//not found in list
	return false;
}

//insert a node into the given list
void insertNode(linkNode* node) {
	//copy list head
	linkNode* iterator = head;
	if(iterator == NULL)
	{//if the list is empty, insert node at beginning
		head = node;
	}

	while(iterator->next != NULL)
	{//find the end of the list
		iterator = iterator->next;
	}
	//instert the node
	iterator->next = node;
}

//make a node out of the given address and data size
linkNode* makeNode(const IPv4Address addr, const int size) {
	//error check
	if(size < 1) return NULL;

	//create node pointer
	linkNode* newNode = (linkNode*)malloc(sizeof(linkNode));

	//error check
	if(newNode == NULL) return NULL;
	
	//initialize node values
	newNode->totalData = size;
	newNode->count = 1;
	newNode->ip = addr;
	newNode->next = NULL;

	return newNode;
}