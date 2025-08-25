#!/bin/bash

# SDN DDoS Detection System Test Script
# This script helps you test the realtime detector application

echo "=========================================="
echo "SDN DDoS Detection System Test Script"
echo "=========================================="

# Check if Ryu is installed
if ! command -v ryu-manager &> /dev/null; then
    echo "Error: Ryu is not installed or not in PATH"
    echo "Please install Ryu first: pip install ryu"
    exit 1
fi

# Check if Mininet is installed
if ! command -v mn &> /dev/null; then
    echo "Error: Mininet is not installed or not in PATH"
    echo "Please install Mininet first"
    exit 1
fi

echo "✓ Ryu and Mininet are available"
echo ""

echo "Starting the SDN DDoS Detection Test..."
echo ""
echo "Step 1: Starting Ryu Controller with our application"
echo "Command: ryu-manager sdn_app/realtime_detector.py"
echo ""
echo "In a new terminal, run the following commands:"
echo ""
echo "# Terminal 2 - Start Mininet:"
echo "sudo mn --controller=remote,ip=127.0.0.1,port=6633 --topo single,3"
echo ""
echo "# In Mininet CLI - Generate normal traffic:"
echo "mininet> h1 iperf -s &"
echo "mininet> h2 iperf -c h1 -t 5"
echo ""
echo "# Wait 15 seconds, then generate attack traffic:"
echo "mininet> h1 hping3 --flood --syn -p 80 10.0.0.2"
echo "# Let it run for 10-15 seconds, then press Ctrl+C"
echo ""
echo "# To exit Mininet:"
echo "mininet> exit"
echo ""
echo "=========================================="

# Start the Ryu controller
ryu-manager sdn_app/realtime_detector.py
