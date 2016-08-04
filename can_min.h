 /*
  * can_min.h
  * This file is part of can-utils
  *
  * Copyright (C) 2016 - Trilys
  *
  * can-utils is free software; you can redistribute it and/or
  * modify it under the terms of the GNU Lesser General Public
  * License as published by the Free Software Foundation; either
  * version 2.1 of the License, or (at your option) any later version.
  *
  * can-utils is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  * Lesser General Public License for more details.
  *
  * You should have received a copy of the GNU Lesser General Public License
  * along with can-utils. If not, see <http://www.gnu.org/licenses/>.
  */

//Send the first sizeOfData bytes of data_to_send to id.
//Return 0 if ok
//ex : CAN_send(0x600,CAN, 8); or CAN_send(0x601,"\x4b\x20\x29\x01\xe8\x03\x00\x00", 8);
char CAN_send(long id, char *data_to_send, char sizeOfData);

// Use CAN_send_offi only if can_send doesn't work with your message
//CAN_send_offi("601#2B0050030000EFFA");
//CAN_send_offi("12345678#2B0050030000EFFA");
//Return 0 if ok
char CAN_send_offi(char *data_to_send);

//Receive CAN from canIDtoFilter marked as decimal. 
//delayToOffInUs : stop CAN_receive after this delay, in microseconds
//canReceived[] is an array which contain the received CAN data.
//sizeOfCAN is the size of CAN data received
char CAN_receive(long canIDtoFilter, long delayToOffInUs, char canReceived[], char *sizeOfCAN);

//Launch CAN_init to launch CAN_*_lite, then CAN_deinit() to close CAN interface.
char CAN_init();

//Same as CAN_receive, but it needs CAN_init() before.
char CAN_receive_lite(long canIDtoFilter, long delayToOffInUs, char canReceived[], char *sizeOfCAN);

//Same as CAN_receive_lite but you can filter with sub-address.
char CAN_receive_filtered_lite(long canIDtoFilter, char addressToFilter[],long delayToOffInUs, char canReceived[], char *sizeOfCAN);

//Same as CAN_receive but you can receive any IDs you want.
//nbIDtoFilter : put how many ID you want to filter
//canIDtoFilter : separate each IDs you want to filter in this array.
//canId will get the ID received.
//canReceived is an array which contain CAN data
//sizeOfCAN is the size of data received.
char CAN_receive_lite_multifilters(unsigned char nbIDtoFilter, long canIDtoFilter[], long delayToOffInUs, long *canId, char canReceived[], char *sizeOfCAN);

//Close sockets
char CAN_deinit();

