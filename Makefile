

rdpscan: src/*.c src/*.h
	gcc -g -O1 src/*.c -lssl -lcrypto -o rdpscan


