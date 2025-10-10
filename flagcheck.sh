#!/bin/bash
lockfile=./.lck
FLAG=/opt/ofbiz/flag
RESEARCH_DIR=/_for_research_please_ignore
LOGFILE=${RESEARCH_DIR}/flag_log.txt

if (set -o noclobber; echo "$$" > "$lockfile") 2> /dev/null; 
then
   # This will cause the lock-file to be deleted in case of a
   # premature exit.
   trap 'rm -f "$lockfile"; exit $?' INT TERM EXIT

   # Critical Section: Here you'd place the code/commands you want
   # to be protected (i.e., not run in multiple processes at once).

   rm -f "$lockfile"
   trap - INT TERM EXIT
else
   echo "Failed to acquire lock-file: $lockfile." 
   echo "Held by process $(cat $lockfile)."
fi

create_flag () {
  RANDVAL=$(tr -dc A-Za-z0-9 </root/urandom_host | head -c 24)
  echo $RANDVAL > $FLAG
}

init_dir () {
  # we could check if folder exists and exit if not
  chown root:root ${RESEARCH_DIR}
  chmod 750 ${RESEARCH_DIR}
}

pack_stuff () {
  tar cfJ ${RESEARCH_DIR}/$(date '+%Y%m%d_%H%M%S').tar.xz /var/log/ids/snoopy.log /var/ossec/logs/alerts/alerts.json /var/ossec/logs/ossec.log /var/log/apache2/* /var/log/ids/ofbiz/*
}

check_flag () {
  if echo "${line}" | grep -qi "$(cat $FLAG)"; then # spicy but should not be injectable
	return 1
  elif echo "${line}" | grep -qi reset; then # spicy but should not be injectable
	return 2
  fi
  return 0
}

do_scoring () {
  NO_ALERTS=$(wc -l < /var/ossec/logs/alerts/alerts.json)
  #NO_ALERTS=$(jq '.rule.id' alerts.json | grep -ve "502" | wc -l) # we ignore rule id 502 
  SCORE_ALERTS=$(jq '.rule.level' /var/ossec/logs/alerts/alerts.json | awk '{s+=$1} END {print s}' -) # we sum all alert levels
}

pr_results () {
  cat /var/ossec/logs/alerts/alerts.log
  echo -n "" > /var/ossec/logs/alerts/alerts.log
  echo -n "" > /var/ossec/logs/alerts/alerts.json
  echo "You had $NO_ALERTS alerts and a score of $SCORE_ALERTS (the lower the better ;)) ... Here is your final flag:"
  echo $SCORE_ALERTS | openssl aes-256-cbc -a -pass pass:oop7SYBH3UIPLtu1zo0y0ONT -iter 1 # decrypt using echo "XX" |  openssl aes-256-cbc -a -iter 1 -pass pass:oop7SYBH3UIPLtu1zo0y0ONT -d
}

kill_proc () {
  killall apache2ctl
  killall apache2
}

if [ ! -f $FLAG ]; then
  create_flag
  exit 0
fi

init_dir
echo Please input flag. If you believe something is wrong you can enter "reset".
read line
echo $(date '+%Y-%m-%d %H:%M:%S') flag submitted "${line}" >> ${LOGFILE}
check_flag
RETVAL=$?
if [[ $RETVAL -eq 1 ]]; then
	echo correct, calculating results
	sleep 20
  pack_stuff
  echo $(date '+%Y-%m-%d %H:%M:%S') stuff packed >> ${LOGFILE}
	do_scoring
	pr_results
  echo $(date '+%Y-%m-%d %H:%M:%S') results printed >> ${LOGFILE}
	kill_proc
elif [[ $RETVAL -eq 2 ]]; then
  echo $(date '+%Y-%m-%d %H:%M:%S') reset requested >> ${LOGFILE}
	kill_proc
else
	echo Sorry ... try again
fi
