#!/bin/bash
DISK_PERCENT_USED=$(df -kh / | tail -n1 | awk '{print $5}'|sed 's/%//')
while [[ $DISK_PERCENT_USED -lt 95 ]]; do
	sleep 10
	DISK_PERCENT_USED=$(df -kh / | tail -n1 | awk '{print $5}'|sed 's/%//')
done
echo DISK ALMOST FULL
exit 1
