/*
 * Trilys_CAN_to_ModBus.c.
 * This file is part of interface_modbus_CAN×2.
 * gcc can_min.c lib_can.c test.c -o test (-D VCAN -D DEBUG)
 * This program manage 3 threads, two will receive information from 2 CAN
 * then send data to each modbus interface and the last is the main.
 *
 * Copyright (C) 2016 - Trilys
 *
 * Trilys_CAN_to_ModBus is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * Trilys_CAN_to_ModBus is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Trilys_CAN_to_ModBus. If not, see <http://www.gnu.org/licenses/>.
 */


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "can_min.h"


//Wait for UART.
//Launch CAN RC with filter received from UART
//Send question from UART through CAN
int main (void)
{
	char canReceived[8];
	char sizeOfCAN;
	char i;
	CAN_init();
//	CAN_receive_lite(long canIDtoFilter, long delayToOffInUs, char canReceived[], char *sizeOfCAN);
	CAN_receive_lite(0x100, 10000000, canReceived, &sizeOfCAN);
	printf("\nCAN_receive_lite : sizeOfCAN=%d, canReceived==",sizeOfCAN);
	for (i = 0; i < sizeOfCAN; i += 1) {
		printf("%02hx ", canReceived[i]);
	}
	CAN_send(0x101, canReceived, sizeOfCAN);
	CAN_deinit();
	printf("\n\n-------End of program-------\n\n");
	return EXIT_SUCCESS;
}

