#!/bin/bash
xinetd -f /etc/xinetd.conf
/root/flagcheck.sh
/root/check-size2.sh &

# speed up wazuh log handling
touch /var/log/ids/ofbiz/access_log..$(date '+%Y-%m-%d')
chown ofbiz:ofbiz /var/log/ids/ofbiz/access_log..$(date '+%Y-%m-%d')

/var/ossec/bin/wazuh-control start

/usr/sbin/apache2ctl -D FOREGROUND &

cd /opt/ofbiz
su - ofbiz -c "./gradlew ofbiz" &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?
