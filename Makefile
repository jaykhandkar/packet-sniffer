STD=gnu99
LIBS=pcap

sniffer: src/main.c src/sniffer.h
	gcc -std=$(STD) -l$(LIBS) src/main.c src/pr_pack.c -o sniffer
clean:
	rm sniffer
