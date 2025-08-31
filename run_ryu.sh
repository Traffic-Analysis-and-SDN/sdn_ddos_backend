#!/bin/bash

# Simple script to run Ryu with global packages
echo "Starting SDN DDoS Detector..."
echo "Using global Python environment"

# Run Ryu normally (global installation with global ML packages)
ryu-manager sdn_app/realtime_detector.py
