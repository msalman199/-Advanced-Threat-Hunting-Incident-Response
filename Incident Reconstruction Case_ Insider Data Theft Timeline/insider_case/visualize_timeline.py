#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import matplotlib.dates as mdates

# Read timeline data
df = pd.read_csv('master_timeline.csv')

# Convert timestamp to datetime
df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
df = df.dropna(subset=['datetime'])

# Create timeline plot
fig, ax = plt.subplots(figsize=(12, 8))

# Color code by source
colors = {'FileSystem': 'blue', 'SystemLog': 'red', 'Network': 'green', 'Registry': 'orange'}
for source in df['source'].unique():
    source_data = df[df['source'] == source]
    ax.scatter(source_data['datetime'], [source] * len(source_data), 
              c=colors.get(source, 'gray'), label=source, alpha=0.7, s=50)

# Format plot
ax.set_xlabel('Timeline')
ax.set_ylabel('Evidence Source')
ax.set_title('Insider Data Theft - Evidence Timeline')
ax.legend()
ax.grid(True, alpha=0.3)

# Format x-axis
ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
ax.xaxis.set_major_locator(mdates.HourLocator(interval=1))
plt.xticks(rotation=45)

plt.tight_layout()
plt.savefig('timeline_visualization.png', dpi=300, bbox_inches='tight')
print("Timeline visualization saved to: timeline_visualization.png")

# Create summary statistics
print("\n=== TIMELINE STATISTICS ===")
print(f"Total Events: {len(df)}")
print(f"Time Range: {df['datetime'].min()} to {df['datetime'].max()}")
print(f"Evidence Sources: {', '.join(df['source'].unique())}")
print(f"Events by Source:")
for source in df['source'].unique():
    count = len(df[df['source'] == source])
    print(f"  {source}: {count} events")
