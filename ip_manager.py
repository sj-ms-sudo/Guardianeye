import sqlite3
import argparse
import logging

logging.basicConfig(filename="logger.log",filemode="a",level="INFO",format='%(asctime)s-%(name)s-%(levelname)s-%(message)s',datefmt='%d/%m/%Y %H:%M:%S')

def get_db():
    conn = sqlite3.connect('ip.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ip_address(
              ip TEXT PRIMARY KEY,
              ip_type TEXT)''')
    logging.info("Ip table created")
    return conn,c

def whitelist():
    while True:
        ip = input("Enter the ip address to whitelist (or exit)\n")
        if ip =="exit":
            break
        conn,c = get_db()
        c.execute("INSERT INTO ip_address(ip,ip_type)VALUES(?,?)",(ip,"WhiteList",))
        logging.info(f"{ip} added to WhiteList")
    conn.commit()
    conn.close()

def blacklist():
    while True:
        ip = input("Enter the ip address to blacklist (or exit)\n")
        if ip =="exit":
            break
        conn,c = get_db()
        c.execute("INSERT INTO ip_address(ip,ip_type)VALUES(?,?)",(ip,"BlackList",))
        logging.info(f"{ip} added to BlackList")
    conn.commit()
    conn.close()

def show_db():
    conn,c = get_db()
    try:
        c.execute("SELECT * FROM ip_address")
        logging.info("ip Table accessed")
        rows = c.fetchall()
    except sqlite3.OperationalError as e:
        logging.error(e)
        print(e)
    print(rows)
    conn.close()

def delete_db():
    conn,c = get_db()
    c.execute("DROP TABLE ip_address")
    logging.info("Ip table deleted")
    print("Ip table deleted")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    logging.info("Ip manager started")
    parser = argparse.ArgumentParser()
    parser.add_argument("-w",action="store_true",help="Add Ips to WhiteList")
    parser.add_argument("-b",action="store_true",help = "Add Ips to Blacklist")
    parser.add_argument("--show",action="store_true",help = "Show the ip table")
    parser.add_argument("--delete",action="store_true",help="Delete table ip")
    args = parser.parse_args()
    if args.w:
        whitelist()
    elif args.b:
        blacklist()
    elif args.show:
        show_db()
    elif args.delete:
        delete_db()
    else:
        print("Invalid Arguments")
        logging.error("Invalid Arguments specified")