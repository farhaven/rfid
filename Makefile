all: rfid

test: rfid
	stty -F /dev/ttyUSB0 115200 cs8 -cstopb -parenb -cooked
	./rfid -d /dev/ttyUSB0

debug: rfid
	gdb ./rfid

rfid: rfid.c
	gcc -std=c99 -o rfid rfid.c

clean:
	rm rfid
