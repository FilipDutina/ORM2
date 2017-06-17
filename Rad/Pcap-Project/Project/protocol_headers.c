#include "protocol_headers.h"
#define ETHERNET_HEADER_SIZE 14
#include "file_manipulation.h"


/*protocol info*/
unsigned char dst_mac[] = {0xc8, 0x0a, 0xa9, 0x68, 0xa1, 0x05}; //mitzi
unsigned char src_mac[] = {0x4c, 0x72, 0xb9, 0x11, 0x63, 0xd4};	//dutja 

unsigned char next_protocol_header_ipv4[2] = { 0x08, 0x00 };
unsigned int next_protocol_header_udp = 17;

unsigned char dst_ip[] = { 192, 168, 0, 40 };	//mitzi
unsigned char src_ip[] = { 192, 168, 0, 52 };	//dutja
//unsigned char src_ip[] = {10,81,2,87};
/*function prototypes*/
unsigned short calculate_checksum(unsigned char*);

unsigned char* setup_header(unsigned char* data_buffer, unsigned char* passed_header, int size_of_current_package)
{
	unsigned int len;
	if (size_of_current_package != DEFAULT_BUFLEN)
	{
		len = TOTAL_HEADER_SIZE + size_of_current_package;
	}
	else
	{
		len = TOTAL_HEADER_SIZE + DEFAULT_BUFLEN;
	}
	unsigned char* header = (unsigned char*)realloc(passed_header, len);
	unsigned short ret_ip_checksum;
	unsigned int just_udp_size = len - ETHERNET_HEADER_SIZE - IP_SIZE;

	/*SETUP ETHERNET HEADER*/
	for (int i = 0; i < 6; i++)
	{
		header[i] = dst_mac[i];
		header[i + 6] = src_mac[i];
	}

	header[12] = (unsigned char)0x8;
	header[13] = (unsigned char)0x00;

	/*SETUP IP HEADER*/
	header[ETHERNET_HEADER_SIZE] = (unsigned char)0x45; //version & IHL
	header[ETHERNET_HEADER_SIZE + 1] = (unsigned char)0x00; //tos
	header[ETHERNET_HEADER_SIZE + 2] = (unsigned char)(len-ETHERNET_HEADER_SIZE >> 8);//Total len in hex, first part
	header[ETHERNET_HEADER_SIZE + 3] = (unsigned char)(len - ETHERNET_HEADER_SIZE & 0xff);// total len in hex, second part
	header[ETHERNET_HEADER_SIZE + 4] = (unsigned char)0x00; //identification first part
	header[ETHERNET_HEADER_SIZE + 5] = (unsigned char)0x00; //identification second part
	header[ETHERNET_HEADER_SIZE + 6] = (unsigned char)0x40;//flags
	header[ETHERNET_HEADER_SIZE + 7] = (unsigned char)0x00;//offset
	header[ETHERNET_HEADER_SIZE + 8] = (unsigned char)0x1e;//ttl
	header[ETHERNET_HEADER_SIZE + 9] = (unsigned char)0x11; //next protocol
	header[ETHERNET_HEADER_SIZE + 12] = (unsigned char)src_ip[0];//src ip pt1
	header[ETHERNET_HEADER_SIZE + 13] = (unsigned char)src_ip[1];//src ip pt2
	header[ETHERNET_HEADER_SIZE + 14] = (unsigned char)src_ip[2];//src ip pt3
	header[ETHERNET_HEADER_SIZE + 15] = (unsigned char)src_ip[3];//src ip pt4
	header[ETHERNET_HEADER_SIZE + 16] = (unsigned char)dst_ip[0];//dst ip pt1
	header[ETHERNET_HEADER_SIZE + 17] = (unsigned char)dst_ip[1];//dst ip pt2
	header[ETHERNET_HEADER_SIZE + 18] = (unsigned char)dst_ip[2];//dst ip pt3
	header[ETHERNET_HEADER_SIZE + 19] = (unsigned char)dst_ip[3];//dst ip pt4
	header[ETHERNET_HEADER_SIZE + 10] = 0;//first part of header checksum
	header[ETHERNET_HEADER_SIZE + 11] = 0; //second part of header checksum

	ret_ip_checksum = 0;
	ret_ip_checksum = calculate_checksum(header);

	header[ETHERNET_HEADER_SIZE + 10] = (unsigned char)(ret_ip_checksum >> 8);//first part of header checksum
	header[ETHERNET_HEADER_SIZE + 11] = (unsigned char)(ret_ip_checksum & 0x00ff); //second part of header checksum

	/*SETUP UDP HEADER*/
	header[ETHERNET_HEADER_SIZE + IP_SIZE] = (unsigned char)(SOURCE_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 1] = (unsigned char)(SOURCE_PORT & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 2] = (unsigned char)(DESTINATION_PORT >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 3] = (unsigned char)(DESTINATION_PORT & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 4] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) >> 8);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 5] = (unsigned char)((len - IP_SIZE - ETHERNET_HEADER_SIZE) & 0x00ff);
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 6] = (unsigned char) 0x00;
	header[ETHERNET_HEADER_SIZE + IP_SIZE + 7] = (unsigned char) 0x00;

	for (int i = ETHERNET_HEADER_SIZE + IP_SIZE + UDP_SIZE, j = 0; i < len; i++, j++)
	{
		header[i] = data_buffer[j];
	}


	return header;
}

unsigned short calculate_checksum(unsigned char* header)
{
	unsigned int header_checksum_calc = 0;

	for (int i = ETHERNET_HEADER_SIZE; i < ETHERNET_HEADER_SIZE + 20; i += 2)
	{
		header_checksum_calc += (header[i] << 8) + header[i + 1];
	}


	while (header_checksum_calc & 0xF0000)
	{
		unsigned int temp = (header_checksum_calc >> 16) + (header_checksum_calc & 0xFFFF);
		header_checksum_calc = temp;
	}

	header_checksum_calc = ~(header_checksum_calc);

	return (unsigned short)header_checksum_calc;
}

