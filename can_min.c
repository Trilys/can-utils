 /*
  * can_min.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include <sys/socket.h> // for sa_family_t 
#include <linux/can.h>
#include <linux/can/error.h>

//Include for CAN
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/can/raw.h>

#include "can_min.h"

#include "config.h"



static volatile char running = 1;

void sigterm(int signo)
{
	running = 0;
}

char CAN_send(long id, char *data_to_send, char sizeOfData)
{
#ifdef DEBUG
	printf("\nIn CAN_send");
#endif
	int s; // can raw socket
	int required_mtu;
	struct sockaddr_can addr;
	struct canfd_frame frame_to_send;
	struct ifreq ifr;
	int i;
#ifdef DEBUG
	printf("\ndata_to_send (%u) = %02lx#", sizeOfData, id);
	for (i = 0; i < sizeOfData; i += 1) {
		printf("%02hhx", data_to_send[i]);
	}
#endif

	//Init frame_to_send_send
	frame_to_send.can_id = id;
	frame_to_send.len = sizeOfData;
	frame_to_send.flags = 0;
	for (i = 0; i < frame_to_send.len; i += 1)
	{
		frame_to_send.data[i] = data_to_send[i];
	}
	required_mtu = 16;

	// open socket
	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}

	strncpy(ifr.ifr_name, CAN_INTERFACE, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_ifindex = if_nametoindex(ifr.ifr_name);
	if (!ifr.ifr_ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;

	setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	// send frame_to_send 
	if (write(s, &frame_to_send, required_mtu) != required_mtu) {
		perror("write");
		return 1;
	}
	close(s);
	return 0;
}

// Use CAN_send_offi only if can_send doesn't work with your message
//CAN_send_offi("601#2B0050030000EFFA");
//CAN_send_offi("12345678#2B0050030000EFFA");
char CAN_send_offi(char *data_to_send)
{
	int s; // can raw socket
	int required_mtu;
	int mtu;
	int enable_canfd = 1;
	struct sockaddr_can addr;
	struct canfd_frame frame;
	struct ifreq ifr;
	required_mtu = parse_canframe(data_to_send, &frame);
#ifdef DEBUG
	printf("data_to_send=%s", data_to_send);
	// parse CAN frame
	printf("frame.can_id=%lx, len=%02hhx, flags=%02hhx, res0=%02hhx, res1=%02hhx, data=", frame.can_id, frame.len, frame.flags, frame.__res0, frame.__res1);
	int i;
	for (i = 0; i < frame.len; i += 1) {
		printf("%02hhx", frame.data[i]);
	}
	printf(".\n");
	printf("required_mtu=%d, mtu=%d, CAN_MTU=%d, CANFD_MTU=%d", required_mtu, mtu, CAN_MTU, CANFD_MTU);
#endif

	// open socket
	if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		perror("socket");
		return 1;
	}

	strncpy(ifr.ifr_name, CAN_INTERFACE, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_ifindex = if_nametoindex(ifr.ifr_name);
	if (!ifr.ifr_ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;

	if (required_mtu > CAN_MTU) {

		// check if the frame fits into the CAN netdevice
		if (ioctl(s, SIOCGIFMTU, &ifr) < 0) {
			perror("SIOCGIFMTU");
			return 1;
		}
		mtu = ifr.ifr_mtu;

		if (mtu != CANFD_MTU) {
			printf("CAN interface ist not CAN FD capable - sorry.\n");
			return 1;
		}

		// interface is ok - try to switch the socket into CAN FD mode
		if (setsockopt(s, SOL_CAN_RAW, CAN_RAW_FD_FRAMES,
			       &enable_canfd, sizeof(enable_canfd))){
			printf("error when enabling CAN FD support\n");
			return 1;
		}

		// ensure discrete CAN FD length values 0..8, 12, 16, 20, 24, 32, 64
		frame.len = can_dlc2len(can_len2dlc(frame.len));
	}

	// disable default receive filter on this RAW socket
	// This is obsolete as we do not read from the socket at all, but for
	// this reason we can remove the receive list in the Kernel to save a
	// little (really a very little!) CPU usage.
	setsockopt(s, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	// send framesizeOfValue
	if (write(s, &frame, required_mtu) != required_mtu) {
		perror("write");
		return 1;
	}
	close(s);
	return 0;
}


//Receive CAN from canIDtoFilter marked as decimal.
char CAN_receive(long canIDtoFilter, long delayToOffInUs, char canReceived[], char *sizeOfCAN){
#ifdef DEBUG
	printf("\nCAN_receive %lx during delay = %ums\n", canIDtoFilter, delayToOffInUs);
#endif
	running = 1;
	fd_set rdfs;
	int s[1];
	int ret;
	struct sockaddr_can addr;
	char ctrlmsg[CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(__u32))];
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	struct can_filter *rfilter;
	struct canfd_frame frame;
	char nbytes, i;
	struct ifreq ifr;
	struct timeval timeout, *timeout_current = NULL, timeout_config = { 0, 0 };
	
	signal(SIGTERM, sigterm);
	signal(SIGHUP, sigterm);
	signal(SIGINT, sigterm);
	//Init time to wait before exit
	timeout_config.tv_usec = delayToOffInUs;
	timeout_config.tv_sec = timeout_config.tv_usec / 1000;
	timeout_config.tv_usec = (timeout_config.tv_usec % 1000) * 1000;
	timeout_current = &timeout;

#ifdef DEBUG
	printf("open %d '%s'. Delay = %ums\n", 0, CAN_INTERFACE, delayToOffInUs);
#endif

	s[0] = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (s[0] < 0) {
		perror("socket");
		return 1;
	}

	//Use interface CAN_INTERFACE
	strncpy(ifr.ifr_name, CAN_INTERFACE, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_ifindex = if_nametoindex(ifr.ifr_name);
	if (!ifr.ifr_ifindex) {
		perror("if_nametoindex");
		return 1;
	}

#ifdef DEBUG
	printf("using interface name '%s'.\n", ifr.ifr_name);
#endif
	if (ioctl(s[0], SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		return 1;
	}
	addr.can_ifindex = ifr.ifr_ifindex;

	//Number filter to alloc
	rfilter = malloc(sizeof(struct can_filter));
	if (!rfilter) {
		fprintf(stderr, "Failed to create filter space!\n");
		return 1;
	}
	// Create filter to get only what we need
	rfilter[0].can_id=canIDtoFilter;
	rfilter[0].can_mask=2047;
	setsockopt(s[0], SOL_CAN_RAW, CAN_RAW_FILTER, rfilter, sizeof(struct can_filter));
	free(rfilter);

	if (bind(s[0], (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	// these settings are static and can be held out of the hot path 
	iov.iov_base = &frame;
	msg.msg_name = &addr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &ctrlmsg;

	while (running) {
		FD_ZERO(&rdfs);
		FD_SET(s[0], &rdfs);

		if (timeout_current)
			*timeout_current = timeout_config;

		if ((ret = select(s[0]+1, &rdfs, NULL, NULL, timeout_current)) <= 0) {
			//perror("select");
			fprintf(stderr, "\nTrilys: END01 due to timeout\n");
			running = 0;
			*sizeOfCAN = 0;
			continue;
		}

		//If CAN/filtered detected
		if (FD_ISSET(s[0], &rdfs)) {
			// these settings may be modified by recvmsg()
			iov.iov_len = sizeof(frame);
			msg.msg_namelen = sizeof(addr);
			msg.msg_controllen = sizeof(ctrlmsg);  
			msg.msg_flags = 0;

			nbytes = recvmsg(s[0], &msg, 0);
			if (nbytes < 0) {
				perror("read");
				return 1;
			}
#ifdef DEBUG
	printf("\nTest100: frame.len=%u, .can_id=%lx, .data=", frame.len,frame.can_id);
	for (i = 0; i < frame.len; i += 1)
	{
		printf(".%02hhx", frame.data[i]);
	}
	printf("\n");
#endif
			*sizeOfCAN = frame.len;
			for (i = 0; i < *sizeOfCAN; i += 1)
			{
				canReceived[i] = frame.data[i];
			}
			running = 0;
		}
		fflush(stdout);
	}
	close(s[0]);
	return 0;
}


//Version lite, we need to use can_receive_lite with CAN_init and CAN_deinit
//Declare global variables for CAN_lite:
int s_sock;
int ret;
struct timeval timeout, *timeout_current = NULL, timeout_config = { 0, 0 };
struct canfd_frame frame;
struct can_filter rfilter;
struct iovec iov;
struct sockaddr_can addr;
struct msghdr msg;
char ctrlmsg[CMSG_SPACE(sizeof(struct timeval)) + CMSG_SPACE(sizeof(__u32))];

char CAN_init(){
#ifdef DEBUG
	printf("\nCAN_init");
#endif

	struct cmsghdr *cmsg;
	struct ifreq ifr;
	
	signal(SIGTERM, sigterm);
	signal(SIGHUP, sigterm);
	signal(SIGINT, sigterm);

	s_sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (s_sock < 0) {
		perror("socket");
		return 1;
	}

	//Use interface CAN_INTERFACE
	strncpy(ifr.ifr_name, CAN_INTERFACE, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_ifindex = if_nametoindex(ifr.ifr_name);
	if (!ifr.ifr_ifindex) {
		perror("if_nametoindex");
		return 1;
	}

#ifdef DEBUG
	printf("using interface name '%s'.\n", ifr.ifr_name);
#endif
	if (ioctl(s_sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		return 1;
	}
	//Utiliser seulement pour l'émission.
//	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;

	setsockopt(s_sock, SOL_CAN_RAW, CAN_RAW_FILTER, NULL, 0);

	if (bind(s_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	// these settings are static and can be held out of the hot path 
	iov.iov_base = &frame;
	msg.msg_name = &addr;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &ctrlmsg;
	
	char sizeOfCAN, canReceived[8] = "";
	CAN_receive_lite(0x581, 1, canReceived, &sizeOfCAN);
}

char CAN_deinit(){
#ifdef DEBUG
	printf("\nCAN_deinit");
#endif
	close(s_sock);
}

//Receive CAN from canIDtoFilter marked as decimal.
char CAN_receive_lite(long canIDtoFilter, long delayToOffInUs, char canReceived[], char *sizeOfCAN){
#ifdef DEBUG
	printf("\nCAN_receive_lite %lx during delay = %ums\n", canIDtoFilter, delayToOffInUs);
#endif
	running = 1;
	fd_set rdfs;
	char nbytes, i;
	//Init time to wait before exit
	timeout_config.tv_usec = delayToOffInUs;
	timeout_config.tv_sec = timeout_config.tv_usec / 1000;
	timeout_config.tv_usec = (timeout_config.tv_usec % 1000) * 1000;
	timeout_current = &timeout;
	
	
	//Number filter to alloc
	//rfilter = malloc(sizeof(struct can_filter));
	//if (!rfilter) {
	//	fprintf(stderr, "Failed to create filter space!\n");
	//	return 1;
	//}
	// Create filter to get only what we need
	rfilter.can_id=canIDtoFilter;
	rfilter.can_mask=2047;
	setsockopt(s_sock, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(struct can_filter));
//	free(rfilter);

#ifdef DEBUG
	printf("open %d '%s'. Delay = %ums\n", 0, CAN_INTERFACE, delayToOffInUs);
#endif

	while (running) {
		FD_ZERO(&rdfs);
		FD_SET(s_sock, &rdfs);

		if (timeout_current)
			*timeout_current = timeout_config;

		if ((ret = select(s_sock+1, &rdfs, NULL, NULL, timeout_current)) <= 0) {
			//perror("select");
			fprintf(stderr, "\nTrilys: END01 due to timeout\n");
			running = 0;
			*sizeOfCAN = 0;
			continue;
		}

		//If CAN/filtered detected
		if (FD_ISSET(s_sock, &rdfs)) {
			// these settings may be modified by recvmsg()
			iov.iov_len = sizeof(frame);
			msg.msg_namelen = sizeof(addr);
			msg.msg_controllen = sizeof(ctrlmsg);  
			msg.msg_flags = 0;

			nbytes = recvmsg(s_sock, &msg, 0);
			if (nbytes < 0) {
				perror("read");
				return 1;
			}
#ifdef DEBUG
	printf("\nInCAN_receive_lite: frame.len=%u, .can_id=%lx, .data=", frame.len,frame.can_id);
	for (i = 0; i < frame.len; i += 1)
	{
		printf(".%02hhx", frame.data[i]);
	}
	printf("\n");
#endif
			*sizeOfCAN = frame.len;
			for (i = 0; i < *sizeOfCAN; i += 1)
			{
				canReceived[i] = frame.data[i];
			}
			running = 0;
		}
		fflush(stdout);
	}
	return 0;
}


char CAN_receive_filtered_lite(long canIDtoFilter, char addressToFilter[],long delayToOffInUs, char canReceived[], char *sizeOfCAN){
#ifdef DEBUG
	printf("\nCAN_receive_filtered_lite %lx#%02hx%02hx:%02hx during delay = %uus\n",addressToFilter[0],addressToFilter[1],addressToFilter[2], canIDtoFilter, delayToOffInUs);
#endif
	running = 1;
	fd_set rdfs;
	char nbytes, i;
	//Init time to wait before exit
	timeout_config.tv_usec = delayToOffInUs;
	timeout_config.tv_sec = timeout_config.tv_usec / 1000;
	timeout_config.tv_usec = (timeout_config.tv_usec % 1000) * 1000;
	timeout_current = &timeout;
	
	// Create filter to get only what we need
	rfilter.can_id=canIDtoFilter;
	rfilter.can_mask=2047;
	setsockopt(s_sock, SOL_CAN_RAW, CAN_RAW_FILTER, &rfilter, sizeof(struct can_filter));
//	free(rfilter);

#ifdef DEBUG
	printf("open %d '%s'. Delay = %ums\n", 0, CAN_INTERFACE, delayToOffInUs);
#endif

	while (running) {
		FD_ZERO(&rdfs);
		FD_SET(s_sock, &rdfs);

		if (timeout_current)
			*timeout_current = timeout_config;

		if ((ret = select(s_sock+1, &rdfs, NULL, NULL, timeout_current)) <= 0) {
			//perror("select");
			fprintf(stderr, "\nTrilys: END01 due to timeout\n");
			running = 0;
			*sizeOfCAN = 0;
			continue;
		}

		//If CAN/filtered detected
		if (FD_ISSET(s_sock, &rdfs)) {
			// these settings may be modified by recvmsg()
			iov.iov_len = sizeof(frame);
			msg.msg_namelen = sizeof(addr);
			msg.msg_controllen = sizeof(ctrlmsg);  
			msg.msg_flags = 0;

			nbytes = recvmsg(s_sock, &msg, 0);
			if (nbytes < 0) {
				perror("read");
				return 1;
			}
#ifdef DEBUG
	printf("\nIn CAN_receive_filtered_lite: frame.len=%u, .can_id=%lx, .data=", frame.len,frame.can_id);
	for (i = 0; i < frame.len; i += 1)
	{
		printf(".%02hhx", frame.data[i]);
	}
	printf("\n");
#endif
			if (addressToFilter[0]==frame.data[1] && addressToFilter[1]==frame.data[2] && addressToFilter[2]==frame.data[3]) {
				*sizeOfCAN = frame.len;
				for (i = 0; i < *sizeOfCAN; i += 1)
				{
					canReceived[i] = frame.data[i];
				}
				running = 0;
			}
		}
		fflush(stdout);
	}
	return 0;
}

struct can_filter *rfilter_multi;

//Receive CAN from canIDtoFilter marked as decimal.
char CAN_receive_lite_multifilters(unsigned char sizeOfFilter, long canIDtoFilter[], long delayToOffInUs, long *canId, char canReceived[], char *sizeOfCAN){
#ifdef DEBUG
	printf("\nCAN_receive_lite_multifilters with %u filters, during delay = %ums\n", sizeOfFilter, delayToOffInUs);
#endif
	running = 1;
	fd_set rdfs;
	char nbytes;
	unsigned int i;
	char output = 0;
	//Init time to wait before exit
	timeout_config.tv_usec = delayToOffInUs;
	timeout_config.tv_sec = timeout_config.tv_usec / 1000;
	timeout_config.tv_usec = (timeout_config.tv_usec % 1000) * 1000;
	timeout_current = &timeout;
	
	
	rfilter_multi = malloc(sizeof(struct can_filter) * sizeOfFilter);
	if (!rfilter_multi) {
		fprintf(stderr, "Failed to create filter space!\n");
		return -1;
	}
	// Create filter to get only what we need
	for (i = 0; i < sizeOfFilter; i += 1)
	{
		rfilter_multi[i].can_id=canIDtoFilter[i];
		rfilter_multi[i].can_mask=2047;
	}
	setsockopt(s_sock, SOL_CAN_RAW, CAN_RAW_FILTER, rfilter_multi, sizeof(struct can_filter) * sizeOfFilter);
	free(rfilter_multi);

#ifdef DEBUG
	printf("open %d '%s'. Delay = %ums\n", 0, CAN_INTERFACE, delayToOffInUs);
#endif

	while (running) {
		FD_ZERO(&rdfs);
		FD_SET(s_sock, &rdfs);

		if (timeout_current)
			*timeout_current = timeout_config;

		if ((ret = select(s_sock+1, &rdfs, NULL, NULL, timeout_current)) <= 0) {
			//perror("select");
			fprintf(stderr, "\nTrilys: END01 due to timeout\n");
			running = 0;
			*sizeOfCAN = 0;
			output = 1;
			continue;
		}

		//If CAN/filtered detected
		if (FD_ISSET(s_sock, &rdfs)) {
			// these settings may be modified by recvmsg()
			iov.iov_len = sizeof(frame);
			msg.msg_namelen = sizeof(addr);
			msg.msg_controllen = sizeof(ctrlmsg);  
			msg.msg_flags = 0;

			nbytes = recvmsg(s_sock, &msg, 0);
			if (nbytes < 0) {
				perror("read");
				return -1;
			}
#ifdef DEBUG
	printf("\nInCAN_receive_lite: frame.len=%u, .can_id=%lx, .data=", frame.len,frame.can_id);
	for (i = 0; i < frame.len; i += 1)
	{
		printf(".%02hhx", frame.data[i]);
	}
	printf("\n");
#endif
			*sizeOfCAN = frame.len;
			*canId = frame.can_id;
			for (i = 0; i < *sizeOfCAN; i += 1)
			{
				canReceived[i] = frame.data[i];
			}
			running = 0;
		}
		fflush(stdout);
	}
	return output;
}

