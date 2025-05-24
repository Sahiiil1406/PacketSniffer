# Network Packet Analysis Chat Application

A sophisticated C-based client-server chat application that combines real-time messaging with advanced network packet analysis capabilities. This application captures and analyzes network traffic while facilitating multi-client chat communication.

## Features

### Chat Functionality
- **Multi-client support**: Server can handle up to 10 concurrent clients
- **Real-time messaging**: Instant message broadcasting between connected clients
- **Connection management**: Automatic client connection/disconnection handling
- **Cross-platform networking**: Uses standard POSIX socket programming

### Network Analysis
- **Live packet capture**: Real-time network packet interception using libpcap
- **Protocol analysis**: Detailed breakdown of TCP, UDP, ICMP, and other protocols
- **Packet statistics**: Comprehensive traffic analysis and reporting
- **Jitter calculation**: Network performance measurement with jitter analysis
- **Packet loss estimation**: Simulated packet loss rate calculation
- **Traffic logging**: Automatic packet capture to `.pcap` files

### Performance Monitoring
- **Real-time statistics**: Live display of network metrics
- **Protocol distribution**: Percentage breakdown of different protocols
- **Network quality metrics**: Jitter and packet loss measurements
- **Periodic reporting**: Automated statistics updates every 10 seconds

## Requirements

### System Dependencies
- Linux/Unix-based operating system
- Root privileges (required for packet capture)
- Network interface access

### Libraries
- `libpcap-dev` - Packet capture library
- Standard C libraries (stdio, stdlib, string, unistd, etc.)
- POSIX socket libraries
- Network interface libraries
## Usage

### Starting the Server
```bash
sudo ./packet_chat server
```

**Important**: Root privileges are required for packet capture functionality.

The server will:
- Display the local IP address and port (default: 8080)
- Begin listening for client connections
- Start capturing network packets on eth0 interface
- Create a `chat_packets.pcap` file for packet logging
- Display periodic network statistics

### Connecting as Client
```bash
./packet_chat client
```

Clients can:
- Connect to the server automatically using local IP detection
- Send messages that are broadcast to all other connected clients
- Receive messages from other clients in real-time
- Disconnect gracefully

### Sample Server Output
```
Server is running on IP: 192.168.1.100, Port: 8080
Waiting for connections...
New client connected. Socket fd is 4, IP is : 192.168.1.101, port : 54321

--- Packet Analysis ---
Packet Length: 74 bytes
Source MAC: aa:bb:cc:dd:ee:ff
Destination MAC: 11:22:33:44:55:66
Source IP: 192.168.1.101
Destination IP: 192.168.1.100
Protocol: TCP

--- Packet Statistics ---
Total Packets: 150
TCP Packets: 120 (80.00%)
UDP Packets: 25 (16.67%)
ICMP Packets: 3 (2.00%)
Other Packets: 2 (1.33%)
Network Jitter: 2.45 ms
Packet Loss: 0.67%
```

## Configuration

### Modifiable Constants
```c
#define PORT 8080              // Server port
#define MAX_BUFFER 1024        // Message buffer size
#define MAX_CLIENTS 10         // Maximum concurrent clients
#define MAX_PACKET_HISTORY 1000 // Packet history for jitter calculation
```

### Network Interface
By default, the application captures packets on `eth0`. To change the interface, modify this line in the `start_server()` function:
```c
handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
```

## Architecture

### Core Components

1. **Socket Server**: Multi-client TCP server using select() for non-blocking I/O
2. **Packet Capture Engine**: libpcap-based network traffic interception
3. **Protocol Analyzer**: Deep packet inspection for various network protocols
4. **Statistics Engine**: Real-time calculation of network performance metrics
5. **Client Handler**: Manages multiple simultaneous client connections

### Data Structures

- `PacketStats`: Comprehensive packet analysis data structure
- Client socket array: Manages multiple client connections
- Packet history buffer: Stores timestamps for jitter calculation

## Security Considerations

- **Root Privileges**: Required for raw packet capture - use with caution
- **Network Exposure**: Server binds to all interfaces (INADDR_ANY)
- **Buffer Management**: Input validation and buffer overflow protection implemented
- **Resource Limits**: Built-in limits on clients and packet history

## Limitations

- **Platform Specific**: Designed for Linux/Unix systems
- **Interface Dependency**: Hardcoded to eth0 network interface
- **Root Required**: Packet capture requires administrative privileges
- **Local Network**: Designed for local network communication
- **Simulated Metrics**: Some packet loss calculations are estimated

## Output Files

- `chat_packets.pcap`: Binary packet capture file compatible with Wireshark and other network analysis tools
