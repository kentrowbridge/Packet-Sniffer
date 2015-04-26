#ifndef __LINKNODE_H__
#define __LINKNODE_H__

#include <iostream>
#include <tins/tins.h>
#include <time.h>

using namespace Tins;

//structures
typedef struct LinkNodeTag {
	IPv4Address ip;
	int count;
	int totalData;
	LinkNodeTag * next;
} LinkNode;

LinkNode* makeNode(IPv4Address addr, int size);
bool searchList(const IPv4Address addr, const int size, LinkNode** head);
void insertNode(LinkNode* node, LinkNode** head);
LinkNode* merge(LinkNode* left, LinkNode* right);
int count(LinkNode* head);
LinkNode* mergeSort(LinkNode* head);


#endif