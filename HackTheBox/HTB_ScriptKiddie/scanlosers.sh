#!/bin/bash

log=$1

echo $log | cut -d' ' -f3- | sort -u | while read ip; do
    echo $ip; exit 1
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done
