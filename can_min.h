/*
 * Used for CAN with UART
 *
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

//Connect to contro.
/*
Check if already connected :
601#4000500100000000
581#4F00500100000000
ID:
601#2B0050030000EFFA
581#6000500300000000
Password:
601#2B005002DF4BEFFA
581#6000500200000000
Vérification:
601#4000500100000000
581#4F00500104000000
             ↑      
Proof of connection
*/
//Return 0 if ok
char CAN_connect();

//Ex1 : 581#6020290100000000 Validation change torque → 42 01|2 2920 01
//Ex2 : 581#4B202901E8030000 Info/Read change torque	42 01|2 2920 01 03E8
void convert_CAN_to_UART(char *can, char *uart, unsigned char *sizeOfValue);
//Ex1 : 581#6020290100000000 Validation change torque → 42 0581 60 2920 01
//Ex2 : 581#4B202901E8030000 Info/Read change torque	42 0581 4B 2920 01 03E8
//			0011223344556677
void convert_CAN_to_UART2(unsigned long canID, char *can, unsigned char sizeOfCAN, char *uart, unsigned char *sizeOfUART);

//Receive CAN from canIDtoFilter marked as decimal.
char CAN_receive(long canIDtoFilter, long delayToOffInUs, char canReceived[], char *sizeOfCAN);


//Launch CAN_init to launch CAN_receive_lite or CAN_connect_lite, then CAN_deinit
char CAN_init();
//Connect to sevcon after CAN_init
char CAN_connect_lite();
char CAN_receive_lite(long canIDtoFilter, long delayToOffInUs, char canReceived[], char *sizeOfCAN);
//size addressToFilter = 3 bytes : address×2+sub-address
char CAN_receive_filtered_lite(long canIDtoFilter, char addressToFilter[],long delayToOffInUs, char canReceived[], char *sizeOfCAN);
char CAN_receive_lite_multifilters(unsigned char nbIDtoFilter, long canIDtoFilter[], long delayToOffInUs, long *canId, char canReceived[], char *sizeOfCAN);
//Close sockets
char CAN_deinit();

