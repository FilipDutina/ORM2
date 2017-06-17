#include "file_manipulation.h"

char** read_from_file(FILE* f, char** data_array, int* num_of_parts, int* size_of_last )
{
	long len = 0;
	int remain = 0;
	int number_of_parts = 0;

	f = fopen("tori.jpg", "rb");
	if (f == NULL)
	{
		printf("No such file found!\n");
		return -1;
	}

	/*searching for end of file*/
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	number_of_parts = (len / DEFAULT_BUFLEN) + 1;
	remain = len % DEFAULT_BUFLEN;
	data_array = (char**)malloc(number_of_parts * sizeof(char*));
	*num_of_parts = number_of_parts;
	*size_of_last = remain;
	rewind(f);

	for (int i = 0; i < number_of_parts - 1; i++)
	{
		data_array[i] = (char*)malloc(DEFAULT_BUFLEN * sizeof(char));
		fread(data_array[i], 1, DEFAULT_BUFLEN, f);
	}

	data_array[number_of_parts - 1] = (char*)malloc((remain) * sizeof(char));
	fread(data_array[number_of_parts - 1], 1, remain, f);

	fclose(f);
	return data_array;
}

unsigned char* convert_to_char(int number, int* num_size)
{
	unsigned char* number_of_elements;
	int malloc_size = 0;
	if (number >= 1000000)
	{
		malloc_size = 7;
	}
	else if (number >= 100000)
	{
		malloc_size = 6;
	}
	else if (number >= 10000)
	{
		malloc_size = 5;
	}
	else if (number >= 1000)
	{
		malloc_size = 4;
	}
	else if (number >= 100)
	{
		malloc_size = 3;
	}
	else if (number >= 10)
	{
		malloc_size = 2;
	}
	else
	{
		malloc_size = 1;
	}
	number_of_elements = (unsigned char*)malloc(malloc_size+1);
	for (int i = 0; i < malloc_size; i++)
	{
		if (number >= 1000000 && number <= 9999999)
		{
			number_of_elements[i] = (number / 1000000 + '0');
			number %= 1000000;
		}
		else if (number >= 100000 && number < 999999)
		{
			number_of_elements[i] = (number / 100000 + '0');
			number %= 100000;
		}
		else if (number >= 10000 && number < 99999)
		{
			number_of_elements[i] = (number / 10000 + '0');
			number %= 10000;
		}
		else if (number >= 1000 && number < 10000)
		{
			number_of_elements[i] = (number / 1000 + '0');
			number %= 1000;
		}
		else if (number >= 100 && number < 1000)
		{
			number_of_elements[i] = (number / 100 + '0');
			number %= 100;
		}
		else if (number >= 10 && number < 99)
		{
			number_of_elements[i] = (number / 10 + '0');
			number %= 10;
		}
		else
		{
			number_of_elements[i] = number + '0';
		}
	}
	number_of_elements[malloc_size] = 0;
	*num_size = malloc_size + 1;
	return number_of_elements;
}