import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter

# Load the CSV data
df = pd.read_csv('network_metrics.csv')  # Replace with your actual CSV file name

# Convert 'Timestamp' column to datetime
df['Timestamp'] = pd.to_datetime(df['Timestamp'])

# Set the timestamp as the index for easier plotting
df.set_index('Timestamp', inplace=True)

# Plotting
plt.figure(figsize=(15, 8))

# Subplot 1: Packets Received
plt.subplot(3, 1, 1)
plt.plot(df.index, df['Packets Received'], label='Packets Received', color='blue')
plt.ylabel('Packets Received')
plt.title('Network Monitoring: Packets Received Over Time')
plt.grid(True)
plt.legend()

# Subplot 2: Packet Loss %
plt.subplot(3, 1, 2)
plt.plot(df.index, df['Packet Loss %'], label='Packet Loss %', color='red')
plt.ylabel('Packet Loss %')
plt.title('Packet Loss Over Time')
plt.grid(True)
plt.legend()

# Subplot 3: Jitter (ms)
plt.subplot(3, 1, 3)
plt.plot(df.index, df['Jitter (ms)'], label='Jitter (ms)', color='green')
plt.xlabel('Time')
plt.ylabel('Jitter (ms)')
plt.title('Jitter Over Time')
plt.grid(True)
plt.legend()

# Format x-axis for better readability
plt.gcf().autofmt_xdate()
date_format = DateFormatter("%H:%M:%S")
plt.gca().xaxis.set_major_formatter(date_format)

plt.tight_layout()

plt.savefig('network_plot.png')
print("Plot saved as network_plot.png")

