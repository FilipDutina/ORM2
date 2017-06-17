#pragma once
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#define DEFAULT_BUFLEN 494

char** read_from_file(FILE*, char**, int*);
unsigned char* convert_to_char(int, int*);