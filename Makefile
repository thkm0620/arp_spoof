all: arp_spoof

arp_spoof: main.o
	g++ -o arp_spoof main.o -lpcap

main.o: main.cpp
	g++ -c -o main.o main.cpp -lpacp

clean:
	rm -f arp_spoof *.o
