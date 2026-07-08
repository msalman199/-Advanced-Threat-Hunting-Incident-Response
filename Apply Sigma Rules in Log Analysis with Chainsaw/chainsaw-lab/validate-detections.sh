#!/bin/bash

echo "=== DETECTION VALIDATION REPORT ==="
echo "Timestamp: $(date)"
echo

# Count different types of detections
echo "Detection Statistics:"
echo "- Total log entries processed: $(chainsaw dump ~/chainsaw-lab/logs/ --csv | wc -l)"
echo "- Sigma rule matches: $(grep -c 'detection' ~/chainsaw-lab/results.json 2>/dev/null || echo '0')"
echo "- High severity alerts: $(grep -c 'high' ~/chainsaw-lab/high-severity.json 2>/dev/null || echo '0')"

echo
echo "File Analysis:"
for file in ~/chainsaw-lab/logs/*.evtx; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        size=$(du -h "$file" | cut -f1)
        echo "- $filename: $size"
    fi
done

echo
echo "Most Common Event IDs:"
chainsaw dump ~/chainsaw-lab/logs/ --csv | cut -d',' -f3 | sort | uniq -c | sort -nr | head -5
