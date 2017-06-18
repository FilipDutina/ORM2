// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2016/2017
// Datoteka: vezba9.c
// ================================================================

/*
	dutja MAG
	18. VI 2017.
*/

// Include libraries
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#else
#include <netinet/in.h>
#include <time.h>
#endif

#include <pcap.h>
#include "protocol_headers.h"
#include "file_manipulation.h"
#include <stdio.h>
#include <time.h>
pcap_t* device_handle;

unsigned char* packet_data;
char** data_array;
FILE* f;
int number_of_packets = 0;
unsigned char keyString[] = "FicoMico";
static unsigned long id;

/*Functions*/
void init_ack_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data);
void sendFirstTwoPackets(unsigned char* data_ext, unsigned char* packet_data, unsigned char* number_of_elements, int packet_len);
void ack_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data);


int main()
{
	int i = 0;
	int packet_len;
	int size_of_last;
	int ethernet_header_size;
	int device_number;
	int sentBytes;

	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned char* data_ext = "zaMiTzija.mp3";
	unsigned char* number_of_elements;

	
	/**************************************************************/
	//Retrieve the device list on the local machine 
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}
	// Count devices and provide jumping to the selected device 
	// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	// Pick one device from the list
	printf("Enter the output interface number (1-%d): ", i);
	scanf("%d", &device_number);

	if (device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return -1;
	}

	// Select the first device...
	device = devices;
	// ...and then jump to chosen devices
	for (i = 0; i < device_number - 1; i++)
	{
		device = device->next;
	}

	/**************************************************************/
	// Open the output adapter 
	if ((device_handle = pcap_open_live(device->name, 65536, 0, 10, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}

	data_array = read_from_file(f, data_array, &number_of_packets, &size_of_last);
	puts("");
	number_of_elements = convert_to_char(number_of_packets, &packet_len);
	printf("Total number of packets: %s\n", number_of_elements);
	puts("");
	printf("Sending data extension and number of packets...\n\n");
	
	/*Sending name and number of packets*/
	sendFirstTwoPackets(data_ext, packet_data, number_of_elements, packet_len);
	
	printf("Data extension sent and number of packets sent!\n\n");

	/*Receiving ACK and if necessary sending first two packets again*/
	while(pcap_loop(device_handle, 0, init_ack_handler, NULL) != -2)
	{
		puts("Sending packets again!\n\n");
		sendFirstTwoPackets(data_ext, packet_data, number_of_elements, packet_len);
		Sleep(50);
	}

	printf("ACK has been received!\n");
	printf("Sending data...\n");
	puts("");
	puts("***************************************************\n\n");
	puts("***************************************************\n\n");

	/*Sending file*/
	for (int i = 0; i < number_of_packets; i++)
	{
		id = i + 3;
		if (i != number_of_packets - 1)
		{
			packet_data = setup_header(data_array[i], packet_data, DEFAULT_BUFLEN, id);
			if (pcap_sendpacket(device_handle, packet_data, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(1);

			/*Receive ACK for current packet*/
			while (pcap_loop(device_handle, 0, ack_handler, NULL) != -2)
			{
				puts("Sending packets again!\n\n");
				pcap_sendpacket(device_handle, packet_data, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE);
				Sleep(1);
			}
		}
		else
		{
			packet_data = setup_header(data_array[i], packet_data, size_of_last, id);
			printf("***Size of last: %d***\n\n", size_of_last+56);

			if (pcap_sendpacket(device_handle, packet_data, size_of_last + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(1);

			/*Receive ACK for current packet*/
			while (pcap_loop(device_handle, 0, ack_handler, NULL) != -2)
			{
				puts("Sending packets again!\n\n");
				pcap_sendpacket(device_handle, packet_data, size_of_last + TOTAL_HEADER_SIZE);
				Sleep(1);
			}
		}
	}
	
	printf("D A T A   S E N T!\nTotal number of data packages sent -> %d + first two packets(name and size)\n", number_of_packets);
	puts("");
	free(packet_data);
	free(data_array);
	pcap_close(device_handle);



	return 0;
}

/******************************************************************************************************************************/
/******************************************************************************************************************************/

void init_ack_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data)
{
	puts("Entered FIRST ACK!\n");
	ethernet_header * eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800)
	{
		printf("eh %x\n", ntohs(eh->type));
		printf("Not an ip packet!\n");
		return 0;
	}

	ip_header * ih = (ip_header *)(packet_data + sizeof(ethernet_header));


	if (ih->next_protocol != 17)
	{
		printf("ip %d\n", ih->next_protocol);
		printf("Not an udp packet!\n");
		return 0;
	}
	unsigned char * custom_header = packet_data + 42;	//string
	unsigned long num = (*(custom_header + 9) << 32) + (*(custom_header + 10) << 24) + (*(custom_header + 11) << 16) + (*(custom_header + 12) << 8) + *(custom_header + 13);

	if (strcmp(custom_header, keyString) == 0 && num == number_of_packets)
	{
		puts("Left FIRST ACK!\n\n");
		pcap_breakloop(device_handle);
	}
}

void sendFirstTwoPackets(unsigned char* data_ext, unsigned char* packet_data, unsigned char* number_of_elements, int packet_len)
{
	for (int i = 0; i < 2; i++)
	{
		id = i + 1;
		if (i == 0)
		{
			packet_data = setup_header(data_ext, packet_data, strlen(data_ext) + 1, id);
			printf("First ID: %d\n", id);
			if (pcap_sendpacket(device_handle, packet_data, strlen(data_ext) + 1 + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				return -1;
			}
		}
		else
		{
			packet_data = setup_header(number_of_elements, packet_data, strlen(number_of_elements) + 1, id);
			printf("Second ID: %d\n\n", id);
			if (pcap_sendpacket(device_handle, packet_data, packet_len + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				return -1;
			}
		}
	}
}

void ack_handler(unsigned char * user, const struct pcap_pkthdr * packet_header, const unsigned char * packet_data)
{
	puts("Entered MAIN ACK!");

	ethernet_header * eh = (ethernet_header *)packet_data;
	if (ntohs(eh->type) != 0x800)
	{
		printf("Not an ip packet!\n");
		return;
	}

	ip_header * ih = (ip_header *)(packet_data + sizeof(ethernet_header));


	if (ih->next_protocol != 17)
	{
		printf("Not an udp packet!\n");
		return 0;
	}
	unsigned char * custom_header = packet_data + 42;	//string
	unsigned long num = (*(custom_header + 9) << 32) + (*(custom_header + 10) << 24) + (*(custom_header + 11) << 16) + (*(custom_header + 12) << 8) + *(custom_header + 13);

	printf("My ID: %d\n", id);
	printf("Returned ID: %d\n", num);

	if (strcmp(custom_header, keyString) == 0 && num == id)
	{
		puts("Left MAIN ACK!\n");
		pcap_breakloop(device_handle);
	}
}