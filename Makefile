all: ruseradd


ruseradd:

	gcc -lcrypt ruseradd.c -o ruseradd -Wall

install:
	
	cp ./ruseradd /usr/local/bin/

clean:
	rm -rf ruseradd
