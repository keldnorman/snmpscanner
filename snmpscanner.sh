#!/bin/bash
#set -x
clear
#-------------------------------------------------------------------------
# Description
#-------------------------------------------------------------------------
# Version 0.3b
# 
# This is a script to test a local network or an entire Country for 
# SNMP agents answering SNMPv2c queries on UDP port 161
# with the SNMP Community String "public" 
# or a custom list.
#
# (C)opyleft Keld Norman, 20 May, 2020
#
# PRE: 
# apt-get update -q && apt-get install parallel snmp ipcalc coreutils masscan nmap curl bc iproute2
#-------------------------------------------------------------------------
# Banner (A Must for 1337'ishness): 
#-------------------------------------------------------------------------
cat << "EOF"

       /^ ^\
      / 0 0 \
      V\ Y /V
       / - \
       |    \
  ..|.,|| (__V..-,

 FETCH SNMP SCANNER
EOF
#-------------------------------------------------
# RUN AS ROOT
#-------------------------------------------------
if [ ${EUID} -ne 0 ]; then 
 printf "\n ### ERROR - This script must have root persmissions (perhaps use sudo)\n\n"
 exit 1
fi
#-------------------------------------------------------------------------
# PROGRAMS NEEDED TO DO THE SCAN
#-------------------------------------------------------------------------
PARALLEL="/usr/bin/parallel"
BASENAME="/usr/bin/basename"
SNMPWALK="/usr/bin/snmpwalk"
MASSCAN="/usr/bin/masscan"
IPCALC="/usr/bin/ipcalc"
PASTE="/usr/bin/paste"
NMAP="/usr/bin/nmap"
CURL="/usr/bin/curl"
BC="/usr/bin/bc"
IP="/sbin/ip"
#-------------------------------------------------------------------------
# VARIABLES
#-------------------------------------------------------------------------
TIMEOUT=60
WORKERS=65
PROCESS_PID=0
PROCESS_FOUND=0
PROGNAME=${0##*/}
SCAN_TIME=$(date +%H%M%S)
SCAN_DATE=$(date +%Y-%m-%d)
WORKDIR="/data/SNMP_SCAN/${SCAN_DATE}"
RUN_DIR="${WORKDIR}/data/clients"
LOCKFILE="/var/run/${PROGNAME%%.*}.pid"
#-------------------------------------------------------------------------
# SNMP COMMUNITY LIST
#-------------------------------------------------------------------------
SNMP_COMMUNITY_LIST="public
private
admin
snmp
Admin
CISCO
Cisco
cisco
access
adm
admin
Public
Private
PUBLIC
PRIVATE
secret
Secret
SECRET
SECRET
SNMP
manager
monitor
0
1234
0392a0
2read
4changes
ANYCOM
C0de
CR52401
IBM
ILMI
Intermec
NoGaH$@!
OrigEquipMfr
SECURITY
SNMP_trap
SUN
SWITCH
SYSTEM
Security
Switch
System
TENmanUFactOryPOWER
TEST
agent
agent_steal
all
all private
all public
apc
bintec
blue
c
cable-d
canon_admin
cc
community
core
debug
default
dilbert
enable
field
field-service
freekevin
fubar
guest
hello
hp_admin
ibm
ilmi
intermec
internal
l2
l3
mngt
netman
network
none
openview
pass
password
pr1v4t3
proxy
publ1c
read
read-only
read-write
readwrite
red
regional
rmon
rmon_admin
ro
root
router
rw
rwa
san-fran
sanfran
scotty
security
seri
snmp
snmpd
snmptrap
solaris
sun
superuser
switch
system
tech
test
test2
tiv0li
tivoli
trap
world
write
xyzzy
yellow"
#-------------------------------------------------
# TRAP
#-------------------------------------------------
trap '
 if [ -f ${WORKDIR}/.running ]; then 
  rm ${WORKDIR}/.running 2>/dev/null
 fi
 OLD_PID=$(cat ${LOCKFILE} 2>/dev/null)
 if [ -e ${LOCKFILE} -a $$ -eq ${OLD_PID:-0} ]; then 
  /bin/rm ${LOCKFILE} >/dev/null 2>&1
 fi
 echo ""
' EXIT 1
#-------------------------------------------------
# Check for lock file and process running
#-------------------------------------------------
if [ -e ${LOCKFILE} ]; then # There is a lockfile
 OLD_PROCESS_PID="$(cat ${LOCKFILE})"
 PROCESS_FOUND="$(ps -p ${OLD_PROCESS_PID} -o pid|grep -cv PID)"
 if [ ${PROCESS_FOUND} -ne 0 ];then # Check if old process is running
  # The PID found in the lockfile is running
  echo ""
  echo "### ERROR - Lockfile ${LOCKFILE} exist."
  echo "            This script is already running with PID: ${OLD_PROCESS_PID}"
  # logger "Script $0 failed - lock file exist - please investigate"
  exit 3
 else # The PID found in the lockfile is NOT running - Remove the lock file
  /bin/rm ${LOCKFILE} >/dev/null 2>&1
 fi
fi
# Create new lock file
echo $$ > $LOCKFILE
#-------------------------------------------------------------------------
# FUNCTIONS
#-------------------------------------------------------------------------
function check_pre_req {
#-------------------------------------------------------------------------
 # RUN AS ROOT
 #-------------
 if [ $(id -u) -ne 0 ]; then 
  printf "\n ### ERROR - This script must be run as root - exiting!\n" 1>&2
  exit 1
 fi
 #-------------
 if [ ! -d ${WORKDIR} ]; then mkdir -p ${WORKDIR} ; fi
 if [ ! -d ${RUN_DIR} ]; then mkdir -p ${RUN_DIR} ; fi
 #-------------
 ERROR=0 # FIND ALLE UTILS
 for PROG in ${NMAP} ${CURL} ${PARALLEL} ${IP} ${IPCALC} ${SNMPWALK} ${PASTE} ${BC} ${MASSCAN} ${BASENAME}; do
  if [ ! -e ${PROG} ] ; then
   printf "\n ### ERROR - Cant run this script - the program ${PROG} is missing!\n"
   ERROR=1
  fi
 done
 if [ ${ERROR:-1} -ne 0 ]; then exit 1; fi
 SCAN_ARRAY[0]='test' || (printf "\n ### ERROR - Arrays not supported in this version of bash.\n" && exit 2) # CHECK FOR ARRAY SUPPORT
}
#-------------------------------------------------------------------------
function select_scan_tool {
#-------------------------------------------------------------------------
 while true; do 
  echo -n ' Select the scan engine
 
  1. MASSCAN   - Extreme fast but might miss a lot of targets
  2. NMAP      - Normally scans 1 mill / day and is very accurate

 Select the engine to use for the scanning: '
 read -s -n1 -r option
  case $option in
   1)   SCAN_METHOD="MASSCAN"
        break;;
   2)   SCAN_METHOD="NMAP" 
        break;;
   *)   clear; printf "\n Invalid option !\n\n" ;;
  esac
 done
 printf "\n"
}
#-------------------------------------------------------------------------
function select_what_to_scan () {
#-------------------------------------------------------------------------
 while true; do 
  echo ""
  echo -n ' Select Scanning method..

  1. NETCARD    - Select a netcard and scan the IP/subnet it has
  2. CUSTOM     - Enter an IP/Subnet to scan
  3. COUNTRY    - Scan all IP adresses of a country or the whole world

 Select a scanning method: '
 read -n1 -r option
  case $option in
   1)   echo ""; select_scan_adapter
        break;;
   2)   echo ""; ask_for_net_to_scan
        break;;
   3)   echo ""; find_all_country_ip
        break;;
   *)   clear; printf "\n Invalid option !\n\n" ;;
  esac
 done
}
#-------------------------------------------------------------------------
function select_scan_adapter {
#-------------------------------------------------------------------------
 ADAPTERS_COUNT=$(${IP} -4 l show|grep -v lo:|grep -c UP)
 if [ ${ADAPTERS_COUNT} -eq 1 ]; then
  ADAPTER=$(${IP} -4 l show|grep UP|grep -v lo:|cut -d ':' -f2|awk '{print $1}'|head -1)
 else
  NETCARDS="$(ls -1 /sys/class/net |grep -v ^lo)"
  for CARD in ${NETCARDS}; do 
   IP_ON_CARD="$(${IP} -o -4 addr show dev ${CARD} 2>/dev/null| cut -d ' ' -f 7)"
   if [ ! -z "${IP_ON_CARD}" ]; then 
    VALID_CARDS="${VALID_CARDS} ${CARD}"
   fi 
  done
  echo ""
  for SHOW_CARD in ${VALID_CARDS}; do 
   IP_ON_CARD="$(${IP} -o -4 addr show dev ${SHOW_CARD} 2>/dev/null| cut -d ' ' -f 7)"
   printf " %-10s: %s\n" ${SHOW_CARD} ${IP_ON_CARD}
  done
  echo ""
  PS3="
 Please select an adapter to use for the scan: "
  NETCARDS="$(ls -1 /sys/class/net |grep -v ^lo)"
  select SELECT_ADAPTER in ${VALID_CARDS}; do
   if [ "${SELECT_ADAPTER:-empty}" != "empty" ]; then
    ADAPTER="${SELECT_ADAPTER}"
    echo ""
    break
   else
    echo -e "\033[2A "
   fi
  done
 fi
 RAW_NET="$(${IP} -o -4 addr show dev ${ADAPTER} 2>/dev/null| cut -d ' ' -f 7)"
 NET="$(${IPCALC} ${RAW_NET}|grep Network|awk '{print $2}')"
}
#-------------------------------------------------------------------------
function ask_for_net_to_scan {
#-------------------------------------------------------------------------
printf "\n\r"
Q="What network do you want to scan for (?.?.?.?/??) ? "
printf "\r ${Q}"
while true; do
 read -r NET
 validate_ip
 if [ ${VALID_NET} -eq 1 ]; then
  echo ${NET} > ${WORKDIR}/snmp_targets.list
  break
 else
  sleep 2
  echo -n -e "\033[1A"
  echo -n -e "\033[1A"
  echo -n -e "                                                        \033[1A"
  echo -n -e "\033[1A"
  echo -n -e "\r                                                                        "
  printf "\r ${Q}"
 fi
done
}
#-------------------------------------------------------------------------
function find_all_country_ip {
#-------------------------------------------------------------------------
COUNTRY_LIST=(AX AF AL DZ AS AD AO AI AQ AG AR AM AW AU AT AZ BS BH BD BB BY BE BZ BJ BM BT BO BQ BA BW BV BR IO BN BG BF BI KH CM CA CV KY CF TD CL CN CX CC CO KM CG CD CK CR CI HR CU CW CY CZ DK DJ DM DO EC EG SV GQ ER EE ET FK FO FJ FI FR GF PF TF GA GM GE DE GH GI GR GL GD GP GU GT GG GN GW GY HT HM VA HN HK HU IS IN ID IR IQ IE IM IL IT JM JP JE JO KZ KE KI KP KR KW KG LA LV LB LS LR LY LI LT LU MO MK MG MW MY MV ML MT MH MQ MR MU YT MX FM MD MC MN ME MS MA MZ MM NA NR NP NL NC NZ NI NE NG NU NF MP NO OM PK PW PS PA PG PY PE PH PN PL PT PR QA RE RO RU RW SH BL KN LC MF PM VC WS SM ST SA SN RS SC SL SG SX SK SI SB SO ZA GS SS ES LK SD SR SJ SZ SE CH SY TW TJ TZ TH TL TG TK TO TT TN TR TM TC TV UG UA AE GB US UM UY UZ VU VE VN VG VI WF EH YE ZM ZW WORLD)
PS3='
 Please enter your choice: '
while [ -z ${COUNTRY} ]; do 
 printf "\n Please select a country to scan: \n\n"
 select COUNTRY in "${COUNTRY_LIST[@]}" ; do
  if [ ! -z "${REPLY##*[!0-9]*}" ]; then
   if [ "${REPLY:-0}" -gt 0 -a "${REPLY:-0}" -le ${#COUNTRY_LIST[@]} ]; then
    break
   fi
  fi
  printf "\n Wrong selection: Select any number from 1-%d\n\n" ${#COUNTRY_LIST[@]}
  echo -e "\033[2A "
 done
done
 printf "\n Getting the latest IP list for country: %s\n" ${COUNTRY^^}
 CURL_DATA=$( ${CURL} --silent "https://stat.ripe.net/data/country-resource-list/data.json?resource=${COUNTRY,,}&v4_format=prefix"|grep -E -o '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-3][0-9])' )
 if [ -z "${CURL_DATA}" ]; then 
  printf " ### ERROR - No data returned from stat.ripe.net..\n"
  exit 1
 else
  NET="$(echo ${CURL_DATA})"
 fi
}
#-------------------------------------------------------------------------
function validate_ip {
#-------------------------------------------------------------------------
VALID_NET=0
local VALID_IP=0
local VALID_SUBNET=0
if [ "${NET}" == "0.0.0.0/0" ]; then
 VALID_NET=1
else
# SCAN IS LOCAL NETWORK OR DEFINDE IN PARAMETER GIVEN
 local ip="$(echo ${NET}|cut -d '/' -f 1 2> /dev/null)"
 local subnet="$(echo ${NET}|cut -d '/' -f 2 2> /dev/null)"
 local number='^[0-9]+([.][0-9]+)?$'
 # TEST IF THE IP IS VALID
 if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  OIFS=$IFS
  IFS='.'
  ip=($ip)
  IFS=$OIFS
  if [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]; then
   VALID_IP=1
  else
   VALID_IP=0
  fi
 fi
 # TEST IF THE SUBNET IS VALID
 if [[ ${subnet:-0} =~ $number ]] ; then
  if [ ${subnet:-0} -eq 0 -o ${subnet:-99} -gt 32 ]; then
   VALID_SUBNET=0
  else
   VALID_SUBNET=1
  fi
 else
  if $(grep -E -q '^(254|252|248|240|224|192|128)\.0\.0\.0|255\.(254|252|248|240|224|192|128|0)\.0\.0|255\.255\.(254|252|248|240|224|192|128|0)\.0|255\.255\.255\.(254|252|248|240|224|192|128|0)' <<< "$subnet"); then
   VALID_SUBNET=1
  else
   VALID_SUBNET=0
  fi
 fi
 # TEST FOR ERRORS
 if [ ${VALID_SUBNET:-0} -ne 1 -o ${VALID_IP:-0} -ne 1  ]; then
  printf "\n ### ERROR - Network to scan (${NET}) is not valid!\n\n"
  VALID_NET=0
 else
  VALID_NET=1
 fi
fi
}
#-------------------------------------------------------------------------
function select_community {
#-------------------------------------------------------------------------
 while true; do 
  echo ""
  echo -n ' Select the community string you want to test the SNMP server with
 
  1. public   - Use the name "public"
  2. CUSTOM   - Enter your own custom search string
  3. BRUTE    - Bruteforce with the list included in this script
  4. NONE     - Stop and do not query open ports with a community

 Select a pre defined tag ( or 2 to enter your own custom string): '
 read -n1 -r option
  case $option in
   1)   SNMP_COMMUNITY="public" 
        echo "${SNMP_COMMUNITY}" > ${WORKDIR}/snmp_community.list
        break;;
   2) printf "\n\n Input your custom search string and press enter: "
        read -n31 -r -e SNMP_COMMUNITY 
        echo "${SNMP_COMMUNITY}" > ${WORKDIR}/snmp_community.list
        break;;
   3)   SNMP_COMMUNITY="${SNMP_COMMUNITY_LIST}"
        echo "${SNMP_COMMUNITY_LIST}" > ${WORKDIR}/snmp_community.list
        break;;
   4)   NO_SNMPWALK=1
        break;;
   *)   clear; printf "\n Invalid option !\n\n" ;;
  esac
 done
 echo ""
}
#-------------------------------------------------------------------------
function scan_snmp {                              # nc 85.204.133.1 -u 161
#-------------------------------------------------------------------------
 printf "\n - Calculating total amount of hosts to scan: "
 TOTAL_HOSTS_TO_SCAN=$(for RANGE in ${NET}; do
  ${IPCALC} -n -b ${RANGE}|grep ^Hosts/Net|awk '{print $2}'
 done | ${PASTE} -s -d+ - | ${BC})
 printf "%s\n\n" ${TOTAL_HOSTS_TO_SCAN}
 printf -- " ---------------------------------------------------------------------\n"
 printf " $(date) - Starting ${SCAN_METHOD} scan of ${TOTAL_HOSTS_TO_SCAN} hosts..\n"
 printf -- " ---------------------------------------------------------------------\n"
 echo "$(date)" > ${WORKDIR}/.running
 case ${SCAN_METHOD:-NMAP} in 

  "NMAP")   SCAN_COMMAND="${NMAP} -T5 -Pn -n --stats-every 1m -p 161 -sU ${NET} -oG ${WORKDIR}/snmp_targets.list"
            printf " ### Running: %s -T5 -n -p 161 -sU %s ...\n" ${NMAP} "${NET:0:30}"
            ${SCAN_COMMAND} 2>&1|while read LINE ; do
             if [ ! -z "${LINE}" ]; then
              if [ $(echo ${LINE}|grep -c "^Stats:") -ne 0 ]; then
               printf " Elapsed: %s hosts: %-9s complete %9s [ next %s undergoing UDP Scan: " $(echo "${LINE}"|tr '(' ' '|awk '{print $2,$4,$7,$9}')
              elif [ $(echo ${LINE}|grep -c "^UDP") -ne 0 ]; then
               printf "%7s procent ETC: %s Remaning %s ]\n" $(echo ${LINE}|tr '(' ' '|awk '{print $5,$8,$9}')
              fi
             fi
             done
             ;;
 
  "MASSCAN") SCAN_COMMAND="${MASSCAN} --ports U:161 ${NET} -oG ${WORKDIR}/snmp_targets.list"
             printf " ### Running: %s --ports U:161 %s ..\n" ${MASSCAN} "${NET:0:30}"
             #printf " ( NB: Open ports reporting is always 0 - please ignore that. )\n"
             ${SCAN_COMMAND} 2>&1
             ;;

  *)         printf " ### ERROR - No valid scan method found!\n"
             exit 1
             ;;
 esac
 printf -- " ---------------------------------------------------------------------\n"
 echo " $(date) - done"
 printf -- " ---------------------------------------------------------------------\n"
 #----------------------------
 printf "\n Found %d target(s) with port 161 open..\n" $(grep -c "161/open/udp" ${WORKDIR}/snmp_targets.list)
}
#-------------------------------------------------------------------------
function run_snmpwalk {
#-------------------------------------------------------------------------
 if [ ${NO_SNMPWALK:-0} -eq 1 ]; then 
  printf " \n ### INFO - Skipping SNMP walk as requested..\n\n"
  return
 fi
 #-----------------------------
 # CHECK COMMUNITIES
 #-----------------------------
 COUNT_COMMUNITIES=$(cat ${WORKDIR}/snmp_community.list 2>/dev/null | wc -l)
 if [ ${COUNT_COMMUNITIES:-0} -eq 0 ]; then 
  printf "\n ### ERROR - No communities specified in ${WORKDIR}/snmp_community.list !\n"
  exit 1
 fi
 #-----------------------------
 # CHECK VALID TARGETS
 #-----------------------------
 VALID_TARGETS="${WORKDIR}/snmp_targets_ip.list"
 grep  "161/open/udp" ${WORKDIR}/snmp_targets.list 2>/dev/null|cut -d" " -f2 > ${VALID_TARGETS}
 COUNT_VALID_TARGETS=$(cat ${VALID_TARGETS} 2>/dev/null|wc -l)
 TARGETS_ERROR=0
 if [ ${COUNT_VALID_TARGETS:-0} -eq 0 ]; then 
  printf "\n ### INFO - No valid targets with status \"open\" found to interrogate!\n"
  let "TARGETS_ERROR++"
 fi
 # UNKNOWN_TARGETS="${WORKDIR}/snmp_targets_filteret_ip.list"
 # grep  "161/open|filtered/udp" ${WORKDIR}/snmp_targets.list 2>/dev/null|cut -d" " -f2 > ${UNKNOWN_TARGETS}
 # COUNT_UNKNOWN_TARGETS=$(cat ${UNKNOWN_TARGETS} 2>/dev/null|wc -l) 
 # if [ ${COUNT_UNKNOWN_TARGETS:-0} -eq 0 ]; then 
 #  printf "\n ### INFO - No targets with status \"open|filtered\" found to interrogate!\n"
 #  let "TARGETS_ERROR++"
 # fi
 if [ ${TARGETS_ERROR:-0} -eq 2 ]; then 
  printf "\n ### ERROR - No targeti(s) found to interrogate!\n"
  exit 1
 fi
 cd ${RUN_DIR}
 #-----------------------------
 # BUILD SNMP WALK SCRIPT
 #-----------------------------
 SCRIPT="${RUN_DIR}/../snmpwalk.sh"
 touch ${SCRIPT}
 chmod 700 ${SCRIPT}
 chown root:root ${SCRIPT}
 echo "#!/bin/bash"                                                                                       > ${SCRIPT}
 echo "if [ ! -d ${RUN_DIR}/\${1} ]; then mkdir -p ${RUN_DIR}/\${1}; fi"                                 >> ${SCRIPT}
 echo "for COMMUNITY in \$(cat ${WORKDIR}/snmp_community.list); do"                                      >> ${SCRIPT} 
 echo " ${SNMPWALK} -v2c -c \${COMMUNITY} \${1} > ${RUN_DIR}/\${1}/\${1}_\${COMMUNITY}_scan_result.log"  >> ${SCRIPT}
 echo "done"                                                                                             >> ${SCRIPT}
 #----------------------------------
 # START SCANNING
 #----------------------------------
 printf "\n ### Testing %d targets with %d communities..\n\n" ${COUNT_VALID_TARGETS} ${COUNT_COMMUNITIES}
 echo " $(date) - Starting scan.."
 printf -- " ---------------------------------------------------\n"
 JOB_LOG="${RUN_DIR}/parallel.snmp.job.log"
 if [ -f ${JOB_LOG} ]; then rm ${JOB_LOG} ; fi
  ${PARALLEL} \
   --shuf     \
   --eta      \
   --plain    \
   --silent   \
   --resume   \
   --timeout ${TIMEOUT}   \
   --max-procs ${WORKERS} \
   --joblog ${JOB_LOG}    \
   -a ${VALID_TARGETS} ${SCRIPT} {} 
 if [ -f ${JOB_LOG} ]; then rm ${JOB_LOG} ; fi
 echo ${PARALLEL} --wait
 printf -- "\n ---------------------------------------------------\n"
 echo " $(date) - done"
}
#-------------------------------------------------------------------------
function generate_report {
#-------------------------------------------------------------------------
 printf "\n Creating the report..\n\n"
 #-------------------------
 # CLEANUP BEFORE REPORTING
 #-------------------------
 EMPTY_RESULTS=$(/usr/bin/find ${RUN_DIR:-/error} -type f -name "*\.*\.*\.*_scan_result.log" -size 0c|wc -l)
 if [ ${EMPTY_RESULTS:-0} -ne 0 ]; then 
  printf " ### INFO - Removing ${EMPTY_RESULTS} empty results..\n\n"
  /usr/bin/find ${RUN_DIR:-/error} -type f -name "*\.*\.*\.*_scan_result.log" -size 0c -delete
 fi 
 /usr/bin/find ${RUN_DIR:-/error} -type d -empty -delete
 #-------------------------
 # REPORT SOMETHING
 #-------------------------
 printf " Found the following results/ommunity: \n\n"
 find ${RUN_DIR}/*/* -type f -name "*\.*\.*\.*_scan_result.log"|cut -d '_' -f3|sort -n|uniq -c

 #-------------------------
 # END OF REPORTING
 #-------------------------
 printf "\n Stopped reporting function..\n"
}
#-------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------
check_pre_req

#select_scan_tool
#select_what_to_scan
#select_community

#scan_snmp
#run_snmpwalk

generate_report
#
#-------------------------------------------------------------------------
# FINISHED PROCESSING
#-------------------------------------------------------------------------
