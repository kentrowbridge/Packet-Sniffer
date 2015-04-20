#include <iostream>
#include <tins/tins.h>
#include <time.h>
#include "sniffer.h"
#include "linknode.h"

using namespace Tins;

/* searchList()
 *
 * addr - IP address to search for
 * size - how much to increment the size of a matching IP link
 * head - pointer to the linked list
 * 
 * This method searches the given linked list for the specified IP address. 
 * If it is found, it increments the number of packets found by 1 and the 
 * total data by the size parameter, and then returns true. Returns false 
 * if IP address is not in the list.
 *
 */
bool searchList(const IPv4Address addr, const int size, LinkNode* head) {
	//param check
	if(size < 0 || head == NULL) return false;

	while(head != NULL)
	{//if this ip address is in the list return true
		if(head->ip == addr) 
		{	
			//increment count on this node
			head->count++;
			head->totalData += size;
			return true;
		}
		head = head->next;
	}
	//not found in list
	return false;
}

/* insertNode()
 *
 * Method takes a linknode and inserts it at the end of the list
 *
 */
void insertNode(LinkNode* node, LinkNode* head) {
	if(node == NULL) return;
	//copy list head
	if(head == NULL)
	{//if the list is empty, insert node at beginning
		head = node;
		return;
	}

	while(head->next != NULL)
	{//find the end of the list
		head = head->next;
	}
	//instert the node
	head->next = node;
}

/* makeNode()
 *
 * Method takes an IP address and the size of a packet and creates
 * a new node that keeps statistics for the specified IP address
 *
 * returns a pointer to the newly created node
 */
LinkNode* makeNode(const IPv4Address addr, const int size) {
	//error check
	if(size < 1) return NULL;
	
	//create node pointer
	LinkNode* newNode = (LinkNode*)malloc(sizeof(LinkNode));

	//error check
	if(newNode == NULL) return NULL;

	//initialize node values
	newNode->totalData = size;
	newNode->count = 1;
	newNode->ip = addr;
	newNode->next = NULL;

	return newNode;
}

/* merge()
 *
 * Method takes two pointers to linked lists and merges them based on 
 * the values of the leading links. It compares each node in the list
 * and inserts the greater of the two into the new list.  
 *
 * returns a pointer to the newly merged list
 */
LinkNode* merge(LinkNode* left, LinkNode* right) {
	if(left == NULL) return right;
	if(right == NULL) return left;

	LinkNode* head = NULL;

	if(left->totalData >= right->totalData)
	{
		head = left;
		head->next = merge(left->next, right);
		return left;
	} else {
		head = right;
		head->next = merge(left, right->next);
		return right;
	}

	return head;
}


/* mergeSort()
 *
 * Method takes a linked list and sorts it using merge sort
 * returns a pointer to the newly sorted list
 */
LinkNode* mergeSort(LinkNode* head) {
	//error
	if(head == NULL){return head;}
	//if head is on its own
	if(head->next == NULL){return head;}
	//split head in two
	LinkNode * left = NULL;
	LinkNode * right = NULL;
	
	int n = count(head);
	LinkNode * middle = head->next;
	LinkNode * previous = head;
	
	int i = 0;
	//moves up half as many times as there are links
	//so middle is the start of the right side and
	//previous is the end of the left
	while(middle != NULL && i < (n/2)-1){
		middle = middle->next;//move up one link
		previous = previous->next;
		i++;
	}
	right = middle;//makes middle the new start of the right half
	previous->next = NULL;//chops the list in half
	left = head;//saves old head to the start of the left half
	
	return merge(mergeSort(left), mergeSort(right));
}

/* count()
 *
 * Method takes a linked list and returns its length
 *
 */
int count(LinkNode* head) {
	int counter = 0;
	while(head != NULL)
	{
		counter++;
		head = head->next;
	}
	return counter;
}