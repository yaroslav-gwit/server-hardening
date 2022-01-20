#!/bin/bash
cut -d: -f3 /etc/group | sort | uniq -d | while read -r x
do
    echo "Duplicate GID ($x) in /etc/group" 
done