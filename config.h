
//Definition for CAN:
#ifdef VCAN
	#define CAN_INTERFACE "vcan0"
#else
	#define CAN_INTERFACE "can0"
#endif

#define MAX_TIME_CANRC_WAITER 3000
#define MAX_NUMBER_ID_FILTER 10
