#!/usr/bin/bash
for rmpo in $(lsblk -o RM,MOUNTPOINT | awk -F " " '/1/ {print $2}'); do findmnt -n "$rmpo" | grep -Ev "\bnodev\b"; done