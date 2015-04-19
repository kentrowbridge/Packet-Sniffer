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
bool searchList(const IPv4Address addr, const int size);
void insertNode(linkNode* node);
void printList(linkNode* head);

//variables
static const int SNIFF_TIME = 60;

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

	printList(head);

	return 0;
}

//process each packet to calculate network usage
bool processPacket(const PDU &pdu) {
	//time check, if past 2 minutes, stop looping
	if(difftime(time(NULL), start) >= SNIFF_TIME)return false;

	//create a raw pdu to retrieve data for pay load size
	const RawPDU &raw = pdu.rfind_pdu<RawPDU>();

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
	if(!searchList(local, raw.payload_size()))
	{
		//if it is not found, add it to the tail
		linkNode* newNode = makeNode(local, raw.payload_size());

		//insert it at the tail
		insertNode(newNode);
	}

	//print to stdout
	std::cout << ip.src_addr() << "  ->  " 
		<< ip.dst_addr() << " : " << raw.payload_size()
		<<std::endl;

	//continue
	return true;
}

void printList(linkNode* head) {
	linkNode* iterator = head;
	while(iterator != NULL)
	{
		std::cout << "====" << iterator->ip <<"===="<<std::endl;
		std::cout << "	number of packets: " << iterator->count <<std::endl;
		std::cout << "	total data received/sent: " << iterator->totalData << std::endl;
		std::cout << "==============" << std::endl;
		iterator = iterator->next;
	}

}

//search the storage list for this ip node
bool searchList(const IPv4Address addr, const int size) {

	linkNode* iterator = head;
	while(iterator != NULL)
	{//if this ip address is in the list return true
		if(iterator->ip == addr) 
		{	
			//increment count on this node
			iterator->count++;
			iterator->totalData += size;
			return true;
		}
		iterator = iterator->next;
	}
	//not found in list
	return false;
}

//insert a node into the given list
void insertNode(linkNode* node) {
	if(node == NULL) return;
	//copy list head
	linkNode* iterator = head;
	if(iterator == NULL)
	{//if the list is empty, insert node at beginning
		head = node;
		return;
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