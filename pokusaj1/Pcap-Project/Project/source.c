// ================================================================
// Katedra: Katedra za racunarsku tehniku i racunarske komunikacije
// Predmet: Osnovi racunarskih mreza 2
// Godina studija: III godina
// Semestar: Letnji (VI)
// Skolska godina: 2016/2017
// Datoteka: vezba9.c
// ================================================================

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

#include <stdio.h>
#include <time.h>
pcap_t* device_handle;

#define TOTAL_HEADER_SIZE 42
#define DEFAULT_BUFLEN 1008

unsigned char* packet_data;
char** data_array;
FILE* f;

int main()
{
	int i = 0;
	int packet_len;
	int size_of_last;
	int number_of_packets = 0;
	int device_number;
	int sentBytes;
	int ethernet_header_size;
	pcap_if_t* devices;
	pcap_if_t* device;
	char error_buffer[PCAP_ERRBUF_SIZE];
	unsigned char* data_ext = "slika.jpg";
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
	printf("Enter the output interface number (1-%d):", i);
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
	if ((device_handle = pcap_open_live(device->name, 65536, 1, 1000, error_buffer)) == NULL)
	{
		printf("\n Unable to open adapter %s.\n", device->name);
		return -1;
	}

	data_array = read_from_file(f, data_array, &number_of_packets, &size_of_last);
	printf("size of last %d\n", size_of_last);
	number_of_elements = convert_to_char(number_of_packets, &packet_len);
	puts(number_of_elements);
	printf("Sending data extension and number of packets...\n");

	for (int i = 0; i < 2; i++)
	{
		if (i == 0)
		{
			packet_data = setup_header(data_ext, packet_data, strlen(data_ext) + 1);
			if (pcap_sendpacket(device_handle, packet_data, strlen(data_ext) + 1 + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				return -1;
			}
		}
		else
		{
			packet_data = setup_header(number_of_elements, packet_data, strlen(number_of_elements) + 1);
			if (pcap_sendpacket(device_handle, packet_data, packet_len + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				return -1;
			}
		}
	}

	printf("Data extension sent and number of packets sent!\n");

	printf("Sending data...\n");
	for (int i = 0; i < number_of_packets; i++)
	{
		if (i != number_of_packets - 1)
		{
			packet_data = setup_header(data_array[i], packet_data, DEFAULT_BUFLEN);
			//printf("Current package : %d\n", i);
			if (pcap_sendpacket(device_handle, packet_data, DEFAULT_BUFLEN + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(2);
		}
		else
		{
			packet_data = setup_header(data_array[i], packet_data, size_of_last);
			//printf("Current package : %d\n", i);
			if (pcap_sendpacket(device_handle, packet_data, size_of_last + TOTAL_HEADER_SIZE) == -1)
			{
				printf("Packet %d not sent!\n", i);
				break;
			}
			Sleep(2);
		}
	}

	printf("Data sent!\n Total number of packages sent -> %d\n", number_of_packets);
	free(packet_data);
	free(data_array);
	pcap_close(device_handle);

	return 0;
}