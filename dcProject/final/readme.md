# Compile the program
gcc -o analyzer advanced_socket_chat.c -lpcap -lpthread

# Run the server (requires sudo for packet capture)
sudo ./advanced_socket_chat