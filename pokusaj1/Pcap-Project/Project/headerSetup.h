#pragma once
/**** UDP header ****/
#define udp_src_port 8080
#define udp_dst_port 8080
#define udp_h_size 8
/*******************/

/**** IPv4 header ****/
#define version 4
#define IHL 5
#define TOS 0
#define identification 0
#define FlagsAndOffset 0x4000
#define TTL 30
#define nxt_protocol 17 //UDP
/*********************/

/**** Ethernet ****/
#define preamble 0b10101010
#define SFD 0b10101011
#define np_type 0x0800 //ipv4
#define eth_h_size 14
/******************/

unsigned short ipv4_header_checksum(unsigned char * packet_data);
unsigned char * udp_header_checksum(unsigned char * packet_data, unsigned int * len);
unsigned char * setup_ethernet_header(unsigned int * len, unsigned char * packet_data);
unsigned char * setup_ipv4_header(unsigned int * len, unsigned char * packet_data);
unsigned char * setup_udp_header(unsigned int * len, unsigned char * packet_data);
unsigned char * setup_custom_header(unsigned int * len, unsigned char * packet_data, long order_number);

const unsigned char dst_mac_address[] = { 0xEC , 0xF4 , 0xBB , 0x91 , 0x42 , 0x08 };//Ethernet Juraj
const unsigned char src_mac_address[] = { 0xC8 , 0x0A , 0xA9 , 0x68 , 0xA1 , 0x05 };//Ethernet Mitzi

const unsigned char src_ipv4_address[] = { 192 , 168 , 0 , 49 };
const unsigned char dst_ipv4_address[] = { 192 , 168 , 0 , 51 };


//const unsigned char src_mac_address[] = { 0x6C , 0x71 , 0xD9 , 0x8F , 0xDF , 0x72 };//Ethernet Robi
//const unsigned char dst_mac_address[] = { 0xF0 , 0x7B , 0xCB , 0x7C , 0xB3 , 0x2B };//WiFi Mitzi











