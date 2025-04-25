# Makefile for extended socket chat application

CC = gcc
CFLAGS = -Wall -pthread
PCAP_LIBS = -lpcap
TARGETS = server client analyzer

all: $(TARGETS)

server: server.c
	$(CC) $(CFLAGS) -o server server.c

client: client.c
	$(CC) $(CFLAGS) -o client client.c

analyzer: analyzer.c
	$(CC) $(CFLAGS) -o analyzer analyzer.c $(PCAP_LIBS)

clean:
	rm -f $(TARGETS)