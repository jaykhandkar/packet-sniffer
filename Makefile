sniffer: src/main.c src/sniffer.h
	gcc src/main.c src/pr_pack.c -lpcap -o sniffer
clean:
	rm sniffer