#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

def create_timeline_chart(csv_file):
    """Create visual timeline of events"""
    
    df = pd.read_csv(csv_file)
    df['datetime'] = pd.to_datetime(df['datetime'])
    
    # Group events by hour
    df['hour'] = df['datetime'].dt.floor('H')
    hourly_counts = df.groupby('hour').size()
    
    plt.figure(figsize=(12, 6))
    plt.plot(hourly_counts.index, hourly_counts.values, marker='o')
    plt.title('Timeline Event Distribution')
    plt.xlabel('Time')
    plt.ylabel('Number of Events')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('timeline_chart.png')
    print("Timeline chart saved as timeline_chart.png")

if __name__ == "__main__":
    create_timeline_chart('timeline.csv')
