#include "headerSetup.h"
#include "string.h"

unsigned char * udp_header_checksum(unsigned char * packet_data, unsigned int * len)
{
	unsigned int checksum = 0;

	if ((*len) % 2)
	{
		(*len)++;
		packet_data[5]++;
	}

	unsigned char * new_packet_data = realloc(packet_data, (*len));

	new_packet_data[(*len) - 1] = 0;

	for (unsigned int i = 0; i < (*len); i += 2)
	{
		checksum += (new_packet_data[i] << 8) + new_packet_data[i + 1];
	}

	checksum += (src_ipv4_address[0] << 8) + src_ipv4_address[1];
	checksum += (src_ipv4_address[2] << 8) + src_ipv4_address[3];
	checksum += (dst_ipv4_address[0] << 8) + dst_ipv4_address[1];
	checksum += (dst_ipv4_address[2] << 8) + dst_ipv4_address[3];
	checksum += nxt_protocol;
	checksum += *len;

	while (checksum & 0xFFFF0000)
	{
		unsigned int tmp = (checksum >> 16) + (checksum & 0xFFFF);
		checksum = tmp;
	}

	checksum = ~checksum;

	new_packet_data[6] = (checksum & 0xFF00) >> 8;
	new_packet_data[7] = checksum & 0xFF;

	return new_packet_data;
}

unsigned short ipv4_header_checksum(unsigned char * packet_data)
{
	unsigned int checksum = 0;
	for (int i = 0; i < IHL * 4; i += 2)
		checksum += (packet_data[i] << 8) + packet_data[i + 1];
	while (checksum & 0xF0000)
	{
		int tmp = (checksum >> 16) + (checksum & 0x0FFFF);
		checksum = tmp;
	}
	return (short)(~checksum);
}

unsigned char * setup_custom_header(unsigned int* len, unsigned char* packet_data, long order_number)
{
	unsigned char* key_string = "RSMVAJFD";
	unsigned int custom_len = (*len) + 14;
	unsigned char* new_packet_data = (unsigned char *)realloc(packet_data, custom_len);

	for (int i = (*len) - 1; i >= 0; i--)
	{
		new_packet_data[i + 14] = new_packet_data[i];
		new_packet_data[i] = 0;
	}

	memcpy(new_packet_data, key_string, 9);
	new_packet_data[9] = (unsigned char)((order_number & 0xFF00000000) >> 32);
	new_packet_data[10] = (unsigned char)((order_number & 0xFF000000) >> 24);
	new_packet_data[11] = (unsigned char)((order_number & 0xFF0000) >> 16);
	new_packet_data[12] = (unsigned char)((order_number & 0xFF00) >> 8);
	new_packet_data[13] = (unsigned char)(order_number & 0xFF);

	*len = custom_len;
	return new_packet_data;
}

unsigned char * setup_udp_header(unsigned int * len, unsigned char * packet_data)
{
	unsigned int udp_len = (*len) + udp_h_size;
	unsigned char * new_packet_data = (unsigned char *)realloc(packet_data, udp_len);

	for (int i = (*len) - 1; i >= 0; i--)
	{
		new_packet_data[i + udp_h_size] = new_packet_data[i];
		new_packet_data[i] = 0;
	}

	new_packet_data[0] = (unsigned char)(udp_src_port >> 8);
	new_packet_data[1] = (unsigned char)(udp_src_port & 0xFF);
	new_packet_data[2] = (unsigned char)(udp_dst_port >> 8);
	new_packet_data[3] = (unsigned char)(udp_dst_port & 0xFF);
	new_packet_data[4] = (unsigned char)(udp_len >> 8);
	new_packet_data[5] = (unsigned char)(udp_len & 0xFF);
	new_packet_data[6] = 0;
	new_packet_data[7] = 0;

	//new_packet_data = udp_header_checksum(new_packet_data, &udp_len);

	*len = udp_len;
	return new_packet_data;
}

unsigned char * setup_ipv4_header(unsigned int * len, unsigned char * packet_data)
{
	unsigned int ipv4_len = (*len) + IHL * 4;
	unsigned char * new_packet_data = (unsigned char *)realloc(packet_data, ipv4_len);

	for (int i = (*len) - 1; i >= 0; i--)
	{
		new_packet_data[i + IHL * 4] = new_packet_data[i];
		new_packet_data[i] = 0;
	}

	new_packet_data[0] = (unsigned char)(version << 4) + IHL;
	new_packet_data[1] = (unsigned char)TOS;
	new_packet_data[2] = (unsigned char)(ipv4_len >> 8);
	new_packet_data[3] = (unsigned char)(ipv4_len & 0xFF);
	new_packet_data[4] = (unsigned char)(identification >> 16);
	new_packet_data[5] = (unsigned char)(identification & 0xFFFF);
	new_packet_data[6] = (unsigned char)(FlagsAndOffset >> 8);
	new_packet_data[7] = (unsigned char)(FlagsAndOffset & 0xFF);
	new_packet_data[8] = (unsigned char)TTL;
	new_packet_data[9] = (unsigned char)nxt_protocol;
	new_packet_data[10] = 0;
	new_packet_data[11] = 0;
	new_packet_data[12] = src_ipv4_address[0];
	new_packet_data[13] = src_ipv4_address[1];
	new_packet_data[14] = src_ipv4_address[2];
	new_packet_data[15] = src_ipv4_address[3];
	new_packet_data[16] = dst_ipv4_address[0];
	new_packet_data[17] = dst_ipv4_address[1];
	new_packet_data[18] = dst_ipv4_address[2];
	new_packet_data[19] = dst_ipv4_address[3];

	short checksum = ipv4_header_checksum(new_packet_data);
	new_packet_data[10] = checksum >> 8;
	new_packet_data[11] = checksum & 0xFF;

	*len = ipv4_len;
	return new_packet_data;
}

unsigned char * setup_ethernet_header(unsigned int * len, unsigned char * packet_data)
{
	unsigned int eth_len = (*len) + eth_h_size;
	unsigned char * new_packet_data = (unsigned char *)realloc(packet_data, eth_len);

	for (int i = (*len) - 1; i >= 0; i--)
	{
		new_packet_data[i + eth_h_size] = new_packet_data[i];
		new_packet_data[i] = 0;
	}

	new_packet_data[0] = dst_mac_address[0];
	new_packet_data[1] = dst_mac_address[1];
	new_packet_data[2] = dst_mac_address[2];
	new_packet_data[3] = dst_mac_address[3];
	new_packet_data[4] = dst_mac_address[4];
	new_packet_data[5] = dst_mac_address[5];
	new_packet_data[6] = src_mac_address[0];
	new_packet_data[7] = src_mac_address[1];
	new_packet_data[8] = src_mac_address[2];
	new_packet_data[9] = src_mac_address[3];
	new_packet_data[10] = src_mac_address[4];
	new_packet_data[11] = src_mac_address[5];
	new_packet_data[12] = (unsigned char)(np_type >> 8);
	new_packet_data[13] = (unsigned char)(np_type & 0xFF);

	*len = eth_len;
	return new_packet_data;
}
