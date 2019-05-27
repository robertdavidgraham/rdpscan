

rdpscan: *.c *.h
	gcc -g -O1 *.c -lssl -lcrypto -o rdpscan


