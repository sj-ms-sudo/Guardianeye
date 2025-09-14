import re
import csv
from datetime import timedelta, datetime
from plyer import notification
import sqlite3
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import sys
import time
import argparse
import logging
import requests
from dotenv import load_dotenv
# Config
load_dotenv()
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
logging.basicConfig(filename="logger.log",filemode="a",level=logging.INFO,format='%(asctime)s-%(name)s-%(levelname)s-%(message)s',datefmt='%d/%m/%Y %H:%M:%S')
LOG_FILE = "/var/log/auth.log"
threshold = 5
window = timedelta(minutes=10)
MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
    "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
    "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}
ts_pattern = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(.*)$"
ip_pattern = r"\d{1,3}(?:\.\d{1,3}){3}"
name_pattern = r"for\s+(\S+)\s+from"
failedlogin = {}       # Counts of failed login attempts (IP or user)
invalid_user = {}      # Counts of invalid user attempts
failed_attempts = {} 

def get_ip_details():
    conn = sqlite3.connect('ip.db')
    c = conn.cursor()
    c.execute("SELECT ip FROM ip_address WHERE ip_type = 'BlackList'")
    blacklist = [row[0] for row in c.fetchall()]
    c.execute("SELECT ip FROM ip_address WHERE ip_type = 'WhiteList'")
    whitelist = [row[0] for row in c.fetchall()]
    conn.close()
    return blacklist,whitelist
#database
def database(count,ip,start,end,reason):
    conn = sqlite3.connect('sus.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS attempts(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              count INTEGER,
              ip TEXT,
              start_time TEXT,
              end_time TEXT,
              reason)''')
    c.execute('''INSERT INTO attempts(
              count,ip,start_time,end_time,reason)
              VALUES(?,?,?,?,?)
              ''',(count,ip,str(start),str(end),reason,))
    conn.commit()
    conn.close()

def send_tele_msg(msg):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id":CHAT_ID,"text":msg}
    try:
        requests.post(url,data=data)
        logging.info("Telegram message Send")
    except Exception as e:
        logging.error("Telegram message not send :",e)
    
#notification
def notify(count , ip , start=0,end=0):
    if count!=0:
        logging.critical(f"{count} attempts from {ip} from {start} to {end}")
        msg = f"{count} failed attempts from ip address {ip} from {start} to {end}"
        title = f"Alert : Suspicious activity from {ip}"
    else:
        logging.critical(f"{ip} in blacklist trying to login")
        msg = f"{ip} in blacklist trying to login"
        title = f"Alert : blacklisted {ip} trying to login"
    notification.notify(title=title,message=msg,timeout=5)
    send_tele_msg(msg)

# Parse timestamp string like "Sep 13 10:12:01"
def parse_timestamp(ts_str):
    parts = ts_str.split()
    month = MONTHS[parts[0]]
    day = int(parts[1])
    hour, minute, second = map(int, parts[2].split(":"))
    return datetime(datetime.now().year, month, day, hour, minute, second)

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self._pos = 0
    def on_modified(self, event):
        blacklist , whitelist = get_ip_details()
        if event.src_path == LOG_FILE:
            with open(LOG_FILE,"r")as f:
                logging.info(f"{LOG_FILE} loaded")
                f.seek(self._pos)
                new_line = f.readlines()
                self._pos = f.tell()
                with open("sample.csv","a",newline="") as csv_file:
                    logging.info(f"CSV file loaded")
                    writer = csv.writer(csv_file)
                    if csv_file.tell() ==0:
                        writer.writerow(["timestamp","message"])
                    for line in new_line:
                        ip_match = re.findall(ip_pattern,line)
                        for ip in ip_match:
                            if ip in blacklist:
                                ts_match = re.match(ts_pattern,line)
                                if ts_match:
                                    timestamp_str = ts_match.group(1)
                                    timestamp = parse_timestamp(timestamp_str)
                                database(1,ip,timestamp,"NULL","Blacklisted IP")
                                notify(0,ip)
                        if "invalid user" in line:
                            ip_match = re.findall(ip_pattern,line)
                            for ip in ip_match:
                                if ip in whitelist:
                                    continue
                                logging.warning(f"Login attempt to invalid user from {ip}")
                                invalid_user[ip] = invalid_user.get(ip,0)+1

                        if "Failed password" in line and "invalid user" not in line:
                            ip_match = re.findall(ip_pattern,line)
                            name_match = re.findall(name_pattern,line)
                            ts_match = re.match(ts_pattern,line)
                            if ts_match:
                                timestamp_str = ts_match.group(1)
                                timestamp = parse_timestamp(timestamp_str)
                                for ip in ip_match:
                                    if ip in whitelist:
                                        continue
                                    logging.warning(f"Failed login attempts from {ip}")
                                    failedlogin[ip] = failedlogin.get(ip,0)+1
                                    failed_attempts.setdefault(ip,[]).append(timestamp)
                                    if failedlogin[ip]>1:
                                        print(f"{failedlogin[ip]} failed attempts on {ip}")
                                    times = failed_attempts[ip]
                                    times.sort()
                                    for i in range(len(times)):
                                        window_start = times[i]
                                        window_end = window_start + window
                                        count = sum(1 for t in times if window_start <= t <= window_end)

                                        if count >= threshold:
                                            database(count, ip, window_start, window_end,"Multiple login attempts")
                                            notify(count, ip, window_start, window_end)
                                            print(f"ALERT: {count} failed attempts from {ip} between {window_start} and {window_end}")
                                            break 
                                for name in name_match:
                                    failedlogin[name] = failedlogin.get(name, 0) + 1
                                    logging.info(f"Failed login attempt for username {name}")
                        ts_match = re.match(ts_pattern,line)
                        if ts_match:
                            ts = ts_match.group(1)
                            msg = ts_match.group(2)
                            writer.writerow([ts,msg])
def show_table():
    conn = sqlite3.connect('sus.db')
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM attempts")
    except sqlite3.OperationalError as e:
        logging.error("Table not found : {e}")
        print("table not found : ",e)
    rows = c.fetchall()
    if rows:
        print(rows,end = "\n")
        logging.info("Database loaded")
    conn.close()
def delete_table():
    conn = sqlite3.connect('sus.db')
    c = conn.cursor()
    c.execute("DROP TABLE attempts")
    logging.info("Table deleted")
    print("TABLE DELETED")
    conn.close()
if __name__ == "__main__":
    logging.info("Program started")
    parser = argparse.ArgumentParser()
    parser.add_argument("--show",action="store_true",help="Show database with suspicious activities")
    parser.add_argument("--delete",action="store_true",help="Delete the table")
    args = parser.parse_args()
    if args.show:
        show_table()
    elif args.delete:
        delete_table()
    else:
        path = os.path.dirname(LOG_FILE) or "."
        event_handler = LogHandler()
        observer = Observer()
        observer.schedule(event_handler,path,recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logging.info("Program exited")
            observer.stop()
        observer.join()
