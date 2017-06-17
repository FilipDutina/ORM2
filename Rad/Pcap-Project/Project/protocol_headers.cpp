#include "protocol_headers.h"
#include <string.h>
#include <pcap.h>

unsigned char dest_address[6]; // destination mac address
unsigned char src_address[6]; // source mac address

void setup_headers(filler_frame* setup)
{
	/*ethernet header*/
	memcpy(&(setup->eh.dest_address), dest_address, 6);
	memcpy(&(setup->eh.src_address), src_address, 6);
	setup->eh.type = 0x800;


	/*ip header*/
	setup->ih.version = 0x04;  //ipv4
	setup->ih.tos = 0x00; // everything normal
	setup->ih.length = htons(sizeof(filler_frame) - sizeof(ethernet_header));
	setup->ih.identification = 0x0000;
	setup->ih.fragm_flags = 0x0000;
	setup->ih.fragm_offset = 0x0000;
	//setup->ih.ttl = ;

	/*upd header*/
}


