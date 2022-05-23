#!/bin/sh
#sguclient daemon

LOG_FILE=/var/log/sguclient.log

clean_log() {

  local logsnum
  logsnum=$(cat $LOG_FILE 2>/dev/null | wc -l)
  [ "$logsnum" -gt 200 ] && {
    echo -e "\n$(date "+%Y-%m-%d %H:%M:%S") 日志文件过长，清空处理！" >$LOG_FILE
  }

}

# 解决有时候"procd_set_param pidfile"命令会失效没能正确的生成pid文件
# 当pid文件没有生成时手动生成pid文件
# 该shell必须放在sgud.sh里，因为只有/etc/init.d/sguclient start_service方法调用完，才会创建sgud.sh的进程，才能获取到pid
if [ -f "/var/run/sgud.sh.pid" ]; then
  echo "pid文件存在."
else
  echo "pid文件不存在，手动创建pid."
	touch /var/run/sgud.sh.pid  >/dev/null 2>&1
	pgrep sgud.sh -f >/var/run/sgud.sh.pid 2>&1 &
fi

# 首次启动sguclient
/bin/sguclient "$@" 1>>$LOG_FILE 2>&1 &
autorestart=$(echo "$@" | grep "\-auto") 
while true; do

  sleep 30
  process=$(pgrep sguclient)
  # 如果用户选择开启重连,那么sgud.sh会保活sguclient
  if [ -n "$autorestart" ]; then   #不可以使用[[]],因为那是bash的扩展
    # 如果存在"sgud.sh.pid"说明并未调用stop_service或者procd守护进程并未退出，应继续保活sguclient
    if [ -z "$process" ]; then
      if [ -f "/var/run/sgud.sh.pid" ]; then
        /bin/sguclient "$@"  1>>$LOG_FILE 2>&1 &
      fi
    fi
  else # 如果不需要重启，一旦sguclient挂掉了，也关闭sgud守护进程
    if [ -z "$process" ]; then
      /etc/init.d/sguclient stop
    fi
  fi
  clean_log

done
