#!/bin/bash

MEMORY_FILE="test_memory.raw"
REPORT_FILE="rootkit_analysis_report.txt"

echo "=== Rootkit Detection Report ===" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "Memory File: $MEMORY_FILE" >> $REPORT_FILE
echo "" >> $REPORT_FILE

echo "=== YARA Scan Results ===" >> $REPORT_FILE
for rule in yara_rules/*.yar; do
    echo "Rule: $rule" >> $REPORT_FILE
    yara "$rule" "$MEMORY_FILE" >> $REPORT_FILE 2>&1
    echo "" >> $REPORT_FILE
done

echo "=== Process Analysis ===" >> $REPORT_FILE
rekall -f "$MEMORY_FILE" --profile Linux64 pslist >> $REPORT_FILE 2>&1

echo "=== Module Analysis ===" >> $REPORT_FILE  
rekall -f "$MEMORY_FILE" --profile Linux64 lsmod >> $REPORT_FILE 2>&1

echo "Report generated: $REPORT_FILE"
