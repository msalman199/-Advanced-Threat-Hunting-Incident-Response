#!/usr/bin/env python3
import sqlite3
import csv
import os

def analyze_firefox_downloads():
    downloads = []
    db_path = '../browser_data/firefox_places.sqlite'
    
    if not os.path.exists(db_path):
        return downloads
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Query for download-related URLs
        cursor.execute("""
            SELECT 
                datetime(moz_historyvisits.visit_date/1000000, 'unixepoch') as visit_time,
                moz_places.url,
                moz_places.title
            FROM moz_places, moz_historyvisits 
            WHERE moz_places.id = moz_historyvisits.place_id
            AND (moz_places.url LIKE '%.zip%' 
                 OR moz_places.url LIKE '%.exe%'
                 OR moz_places.url LIKE '%.pdf%'
                 OR moz_places.url LIKE '%.doc%'
                 OR moz_places.url LIKE '%download%')
            ORDER BY visit_time DESC
        """)
        
        downloads = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"Error analyzing Firefox downloads: {e}")
    
    return downloads

def analyze_chromium_downloads():
    downloads = []
    db_path = '../browser_data/chromium_history.db'
    
    if not os.path.exists(db_path):
        return downloads
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Query for download-related URLs
        cursor.execute("""
            SELECT 
                datetime(visits.visit_time/1000000-11644473600, 'unixepoch') as visit_time,
                urls.url,
                urls.title
            FROM urls, visits 
            WHERE urls.id = visits.url
            AND (urls.url LIKE '%.zip%' 
                 OR urls.url LIKE '%.exe%'
                 OR urls.url LIKE '%.pdf%'
                 OR urls.url LIKE '%.doc%'
                 OR urls.url LIKE '%download%')
            ORDER BY visit_time DESC
        """)
        
        downloads = cursor.fetchall()
        conn.close()
    except Exception as e:
        print(f"Error analyzing Chromium downloads: {e}")
    
    return downloads

def main():
    print("=== Download Activity Analysis ===")
    
    firefox_downloads = analyze_firefox_downloads()
    chromium_downloads = analyze_chromium_downloads()
    
    all_downloads = []
    
    for download in firefox_downloads:
        all_downloads.append(('Firefox', download[0], download[1], download[2]))
    
    for download in chromium_downloads:
        all_downloads.append(('Chromium', download[0], download[1], download[2]))
    
    # Sort by timestamp
    all_downloads.sort(key=lambda x: x[1], reverse=True)
    
    if all_downloads:
        print(f"Found {len(all_downloads)} download-related activities:")
        for browser, timestamp, url, title in all_downloads[:10]:
            print(f"{timestamp} [{browser}]: {url}")
            if title:
                print(f"  Title: {title}")
            print()
    else:
        print("No download activities detected")

if __name__ == "__main__":
    main()
