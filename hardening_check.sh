#!/bin/bash
cd /root/server-hardening
git pull &>/dev/null
source bin/activate
./centos7-hardening.py