#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please use sudo, or run as root."
  exit
fi

cd /root/server-hardening
git pull &>/dev/null
source bin/activate
./centos7-hardening.py