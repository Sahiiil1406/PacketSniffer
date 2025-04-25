# 🔍 Network Analysis Toolkit

This project enables real-time packet forwarding, capture, and visualization using a server-client architecture with SSH tunneling, packet analysis, and Python graphing tools.

---

## 🚀 Setup & Usage

Follow the steps below to run the full pipeline:

---

### ✅ Step 1: Start the Server

```bash
./server
```

Forward the local port using [Serveo](https://serveo.net):

```bash
ssh -R 12345:localhost:8080 serveo.net
```

This exposes your local server on a public IP via SSH tunneling.

---

### ✅ Step 2: Start the Client

On the client machine, connect to the server’s public IP:

```bash
./client <serveo_ip_address> 12345
```

> 💡 Use `ping serveo.net` to get the resolved IP address.

---

### ✅ Step 3: Start the Analyzer

```bash
./analyzer
```

This listens for network packets and prepares data for analysis.

---

### ✅ Step 4: Analyze Using Wireshark

Open [Wireshark](https://www.wireshark.org/) and inspect network traffic on the appropriate interface.

---

### ✅ Step 5: Generate Graphs with Python

Run the following to visualize captured metrics:

```bash
python3 plot_graphs.py
```

This script generates plots for:

- Latency
- Packet loss
- Jitter
- Throughput

---

## 📆 Components

- `server`: Accepts client connections, forwards packets.
- `client`: Connects to the server via Serveo and sends packets.
- `analyzer`: Captures traffic for analysis.
- `plot_graphs.py`: Python visualization script.

---

## 📊 Features

- Real-time packet forwarding via SSH
- End-to-end traffic monitoring
- Wireshark support
- Graph generation using Python

---

## 🛠️ Requirements

- **Wireshark** (optional)
- **Python 3.x**
- Python libraries:
  - `matplotlib`
  - `seaborn`
  - `pandas`

Install Python dependencies:

```bash
pip install matplotlib seaborn pandas
```

---

## ⚠️ Notes

- Make sure port `12345` is open on your network.
- Serveo may occasionally change IPs — always double-check with `ping`.
- Internet connection is required for SSH tunnel.

---

## 📧 Contact

Feel free to reach out for any issues or improvements!

