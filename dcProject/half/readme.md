gcc -o packet_sniffer packet_sniffer.c -lpcap -Wall -O2

./packet_sniffer

wireshark -r capture.pcap
