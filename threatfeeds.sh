#!/bin/bash 
# Script to download thread feeds and parse them for Splunk
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
# - Banlist Feedand then strips any junk/formatting 

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

FEED_DIR="/var/log/threatfeeds"
FEED_TMP="/var/log/threatfeeds/tmp"

#==============================================================================
# Validate that /var/log/threatfeeds exists and create if it doesnt
#==============================================================================

if [ ! -d /var/log/threatfeeds ]; then
    mkdir -p $FEED_DIR
fi

#==============================================================================
# Validate that $FEED_DIR/tmp exists and create if it doesnt
#==============================================================================

if [ ! -d $FEED_DIR/tmp ]; then
    mkdir -p $FEED_TMP
fi

#============================================================================================
# Emerging Threats - Shadowserver C&C List, Spamhaus DROP Nets, Dshield Top Attackers, Feodo
#=====================================================================================

wget http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt -O $FEED_TMP/emerging-Block-IPs.txt --no-check-certificate

# Shadowserver is currently not publishing this data, so the feed is always empty
#cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Shadowserver C&C List/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed 's/$/ Shadowserver IP/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_shadowserver_ips.txt

#cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/#Spamhaus DROP Nets/d' -e '/#/,$d' | xargs -n 1 prips | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Spamhaus IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_spamhaus_drop_ips.txt

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/#Dshield Top Attackers/d' -e '/#/,$d' | xargs -n 1 prips | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Dshield IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_dshield_ips.txt

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Feodo/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Feodo IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_feodo_ips.txt

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Palevo/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Palevo IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_palevo_ips.txt

cat $FEED_TMP/emerging-Block-IPs.txt | sed -e '1,/# \Zeus/d' -e '/#/,$d' | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Zeus IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_zeus_ips.txt

rm $FEED_TMP/emerging-Block-IPs.txt

#==============================================================================
# Emerging Threats - Compromised IP List
#==============================================================================

wget http://rules.emergingthreats.net/blockrules/compromised-ips.txt -O $FEED_TMP/compromised-ips.txt --no-check-certificate

cat $FEED_TMP/compromised-ips.txt | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Compromised IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/emerging_threats_compromised_ips.txt

rm $FEED_TMP/compromised-ips.txt

#==============================================================================
# Binary Defense Systems Artillery Threat Intelligence Feed and Banlist Feed
#==============================================================================

wget http://www.binarydefense.com/banlist.txt -O $FEED_TMP/binary_defense_ips.txt --no-check-certificate

cat $FEED_TMP/binary_defense_ips.txt | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Binary Defense IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/binary_defense_ban_list.txt

rm $FEED_TMP/binary_defense_ips.txt

#==============================================================================
# AlienVault - IP Reputation Database
#==============================================================================

wget https://reputation.alienvault.com/reputation.snort.gz -P $FEED_TMP --no-check-certificate

gzip -d $FEED_TMP/reputation.snort.gz

cat $FEED_TMP/reputation.snort | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/\<Host\>//g'  | sed "s/;/ /g" | sed "s/# /threat_type=/" | sed "s/  / alt_threat_type=/" | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/av_ip_rep_list.txt

rm $FEED_TMP/reputation.snort

#==============================================================================
# SSLBL - SSL Blacklist
#==============================================================================

wget https://sslbl.abuse.ch/blacklist/sslipblacklist.csv -O $FEED_TMP/sslipblacklist.csv --no-check-certificate

cat $FEED_TMP/sslipblacklist.csv | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | cut -d',' -f1,3 | sed 's/\<C&C\>//g' | sed "s/,/ threat=/" | sed 's/$/ threat_type="SSLBL IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/sslipblacklist.txt

rm $FEED_TMP/sslipblacklist.csv

#==============================================================================
# Malc0de - Malc0de Blacklist
#==============================================================================

wget http://malc0de.com/bl/IP_Blacklist.txt -O $FEED_TMP/IP_Blacklist.txt --no-check-certificate

cat $FEED_TMP/IP_Blacklist.txt | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Malc0de IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/malc0de_black_list.txt

rm $FEED_TMP/IP_Blacklist.txt

#==============================================================================
# ZeuS Tracker - IP Block List
# Keep for archive only - integrated into Emerging Threats
#==============================================================================

#wget https://zeustracker.abuse.ch/blocklist.php?download=badips -O $FEED_TMP/zeustracker.txt --no-check-certificate
#
#cat $FEED_TMP/zeustracker.txt | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Zeus IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }'>> $FEED_DIR/zeus_ip_block_list.txt
#
#rm $FEED_TMP/zeustracker.txt

#==============================================================================
# Palevo Tracker - IP Block List
# Keep for archive only - integrated into Emerging Threats
#==============================================================================

#wget https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist -O $FEED_TMP/palevotracker.txt --no-check-certificate
#
#cat $FEED_TMP/palevotracker.txt | sed -n '/^[0-9]/p' | sed -e 's/^/threat_ip=/' | sed 's/$/ threat_type="Malc0de IP"/' | awk '{ print strftime("%Y-%m-%d %H:%M:%S"), $0; }' >> $FEED_DIR/palevo_ip_block_list.txt
#
#rm $FEED_TMP/palevotracker.txt

#==============================================================================
# END
#==============================================================================

