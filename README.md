# can-utils
Linux-CAN / SocketCAN user space applications

This is the minimum library you need to work on every CAN interface. You need to set the interface in the config.h file.

Compile the test.c file on a linux system :
  gcc can_min.c lib_can.c test.c -o test
The test file will forward a CAN data from address 0x100 to 0x101.
