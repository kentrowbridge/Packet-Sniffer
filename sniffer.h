#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <iostream>
#include <tins/tins.h>
#include <time.h>
#include "linknode.h"

using namespace Tins;

//method declarations
bool processPacket(const PDU &pdu);
void printList(LinkNode** head);

//variables
static const int SNIFF_TIME = 180;

#endif
