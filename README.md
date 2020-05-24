# snmpscanner
Test a country for SNMP agents answering SNMPv2c queries on UDP port 161 with the SNMP Community String "public"

# PRE: 
apt-get update -q && apt-get install parallel snmp ipcalc coreutils nmap curl bc iproute2

# Syntax: 
./snmpscanner.sh
