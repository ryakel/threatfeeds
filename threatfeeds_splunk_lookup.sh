#!/bin/bash 
# Script to download thread feeds and parse them for Splunk
# This script creates a single CSV file used for a Splunk lookup table
# Feeds Include:
# - Emerging Threats - Shadowserver C&C List
# - Spamhaus DROP Nets
# - Dshield Top Attackers, 
# - Known RBN Nets and IPs
# - Compromised IP List 
# - RBN Malvertisers IP List
# - AlienVault - IP Reputation Database
# - ZeuS Tracker - IP Block List
# - SpyEye Tracker - IP Block List
# - Palevo Tracker - IP Block List 
# - SSLBL - SSL Blacklist
# - Malc0de Blacklist
# - Binary Defense Systems Artillery 
# - Threat Intelligence Feed
# - Banlist Feed and then strips any junk/formatting 

# This script also logs in key=value pairs for easier ingestion into Splunk

#==============================================================================
# @@@ !! IMPORTANT NOTE - This script requires prips to work correctly  !! @@@
#==============================================================================
# sudo apt-get install prips

#==============================================================================
# Fix error if calling script from Splunk
#==============================================================================

unset LD_LIBRARY_PATH

#==============================================================================
# Global Variables
#==============================================================================

FEED_DIR="/tmp/threatfeeds"
FEED_TMP=$FEED_DIR/tmp
SPLUNK_DIR="/opt/splunk/etc/apps/search/lookups"
LOOKUP_FILE=$SPLUNK_DIR/threatfeed.csv
VAR_MSG="/var/log/messages"

#==============================================================================
# Validate that /var/log/threatfeeds exists and create if it doesnt
#==============================================================================

if [ ! -d $FEED_DIR ]; then
    mkdir -p $FEED_DIR
fi

#==============================================================================
# Validate that $FEED_DIR/tmp exists and create if it doesnt
#==============================================================================

if [ ! -d $FEED_DIR/tmp ]; then
    mkdir -p $FEED_TMP
fi

#==============================================================================
# Validate that $SPLUNK_DIR exists and error if it doesnt
#==============================================================================

if [ ! -d $SPLUNK_DIR ]; then
    echo "Splunk directory doesn't exist in $SPLUNK_DIR - Is it installed?" | tee -a $VAR_MSG
    exit 127
fi

#==============================================================================
# Create CSV Shell
#==============================================================================

echo "threat_ip,threat,threat_type,alt_threat_type" > $LOOKUP_FILE

#============================================================================================
# Emerging Threats - Shadowserver C&C List, Spamhaus DROP Nets, Dshield Top Attackers, Feodo
#=====================================================================================

wget http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -O $FEED_TMP/emerging-Block-IPs.txt --no-check-certificate

# Shadowserver is currently not publishing this data, so the feed is always empty
#cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Shadowserver C&C List/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed 's/$/ Shadowserver IP/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_shadowserver_ips.txt

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/#Spamhaus DROP Nets/d' -e '/#/,$d' | xargs -n 1 prips | sed -n '/^[0-9]/p' | sed 's/$/,,Spamhaus_DROP_Nets,,/' >> $LOOKUP_FILE

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/#Dshield Top Attackers/d' -e '/#/,$d' | xargs -n 1 prips | sed -n '/^[0-9]/p' | sed 's/$/,,Dshield_Top_Attackers,,/' >> $LOOKUP_FILE

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Feodo/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed 's/$/,,Feodo_IP,,/' >> $LOOKUP_FILE

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Palevo/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed 's/$/,,Palevo_IP,,/' >> $LOOKUP_FILE

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Zeus/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed 's/$/,,Zeus_IP,,/' >> $LOOKUP_FILE

#==============================================================================
# Emerging Threats - Compromised IP List
#==============================================================================

wget http://rules.emergingthreats.net/blockrules/compromised-ips.txt -O $FEED_TMP/compromised-ips.txt --no-check-certificate

cat $FEED_TMP/compromised-ips.txt | sed -n '/^[0-9]/p' | sed 's/$/,,Compromised_IP,,/' >> $LOOKUP_FILE

#==============================================================================
# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
#==============================================================================

wget http://www.binarydefense.com/banlist.txt -O $FEED_TMP/binary_defense_ips.txt --no-check-certificate

cat $FEED_TMP/binary_defense_ips.txt | sed -n '/^[0-9]/p' | sed 's/$/,,Binary_Defense_IP,,/' >> $LOOKUP_FILE

#==============================================================================
# AlienVault - IP Reputation Database
#==============================================================================

wget https://reputation.alienvault.com/reputation.snort.gz -P $FEED_TMP --no-check-certificate

gzip -d $FEED_TMP/reputation.snort.gz

cat $FEED_TMP/reputation.snort | sed -n '/^[0-9]/p' | sed 's/ # /,,/g' | sed 's/;/,/g' | sed 's/ /_/g' >> $LOOKUP_FILE

#==============================================================================
# SSLBL - SSL Blacklist
#==============================================================================

wget https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O $FEED_TMP/sslipblacklist.csv --no-check-certificate

cat $FEED_TMP/sslipblacklist.csv | sed -n '/^[0-9]/p' | cut -d',' -f1,3 | sed 's/ /_/g' | sed 's/C&C/C2,/g' | sed 's/$/SSLB_IP/g' >> $LOOKUP_FILE

#==============================================================================
# Malc0de - Malc0de Blacklist
#==============================================================================

wget http://malc0de.com/bl/IP_Blacklist.txt -O $FEED_TMP/IP_Blacklist.txt --no-check-certificate

cat $FEED_TMP/IP_Blacklist.txt | sed -n '/^[0-9]/p' | sed 's/$/,,Malc0de_IP,,/' >> $LOOKUP_FILE

#==============================================================================
# ZeuS Tracker - IP Block List
# Keep for archive only - integrated into Emerging Threats
#==============================================================================

#URL: https://zeustracker.abuse.ch/blocklist.php?download=badips

#==============================================================================
# Palevo Tracker - IP Block List
# Keep for archive only - integrated into Emerging Threats
#==============================================================================

#URL: https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist

#==============================================================================
# Clean Up FEED_DIR and FEED_TMP
#==============================================================================

if  [ -d $FEED_DIR ]; then
    rm -rf $FEED_DIR
fi

#==============================================================================
# END
#==============================================================================
