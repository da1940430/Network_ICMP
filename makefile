all:ipscanner

ipscanner:main.c fill_packet.h fill_packet.c 
	gcc main.c fill_packet.h fill_packet.c -o ipscanner -pthread

clean:
	rm ipscanner