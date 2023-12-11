#!/bin/bash
echo "Updating hosts"
./custom-hosts.sh
cat /etc/hosts

catalina.sh run