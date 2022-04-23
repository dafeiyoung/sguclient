#!/bin/sh
#sguclient daemon 

LOG_FILE=/var/log/sguclient.log

clean_log() {
	
 	local logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
	[ "$logsnum" -gt 300 ] && {
		tail -n 10 $LOG_FILE >$LOG_FILE
		echo "$(date "+%Y-%m-%d %H:%M:%S") 日志文件过长，清空处理！" >>$LOG_FILE
	}
}

/bin/sguclient $@ 2&>1  1>>$LOG_FILE  & 

while true
do
	sleep 30
	process=`pgrep sguclient`
	if [  -z "$process" ];then
		if [  -f "/tmp/SGU_immortality" ]; then 
			/bin/sguclient $@ 2&>1 1>>$LOG_FILE  &
		else
			#exit  #不要退出,否则会引起procd重启sgud.sh导致sguclient又被启动
			sleep 114514
		fi   
	fi
	clean_log
done 







