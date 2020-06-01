#!/bin/bash
clear
SCAN_DIR="/data/SNMP_SCAN/*/data/clients/"
printf "\n Add targets to LibreNMS..\n\n"
find ${SCAN_DIR} -name "*_public_scan_result.log" -type f|cut -d "/" -f 8-|cut -d "_" -f1,2|tr '_' ' '|while read IP COMMUNITY; do 
 ADD_MSG=$(runuser -l librenms -c "./addhost.php -f -b ${IP} ${COMMUNITY} v2c 161 udp" 2>&1)
 RC=$?
 printf " %-15s with Community %-30s" ${IP} "\"${COMMUNITY}\""
 if [ $RC -eq 0 ]; then 
  printf "[OK]\n"
 else
  printf "[FAILED]\n"
 fi
done