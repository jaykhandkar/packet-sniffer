STD=gnu99
LIBS=pcap
CC=gcc

sniffer: src/main.c src/sniffer.h
	$(CC) -std=$(STD) src/main.c src/pr_pack.c -o sniffer -l$(LIBS)
clean:
	rm sniffer
