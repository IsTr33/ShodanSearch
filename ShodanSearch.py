"""
Created 2019.1.5 by IsTr33

Modified 2019.3.31
Fixed the IP invalid bug.
"""

# -*- coding: UTF-8 -*-
import shodan
import time
import requests
from bs4 import BeautifulSoup
import re
import sys
reload(sys)
sys.setdefaultencoding('utf8')

#Fill in Shodan API Key
SHODAN_API_KEY = "XXX"

api = shodan.Shodan(SHODAN_API_KEY)

def get_ip_list(file):
    pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    with open(file) as f:
        file_data = f.read()
    ip_list = pattern.findall(file_data)
    # Remove duplicate IP addresses
    ip_list_new = []
    for i in ip_list:
        if i not in ip_list_new:
            ip_list_new.append(i)
    return ip_list_new

def get_http_title(ip, port, protocol, flag=0):
    url = protocol+"://"+ip+":"+port
    try:
        res = requests.get(protocol+"://"+ip+":"+port, verify=False)

        #When the page encoding is "ISO-8859-1", the actual page encoding format cannot be confirmed. If an exception occurs, set the flag, switch the encoding format and try again.
        if res.encoding == 'ISO-8859-1':
            if flag == 0:
                res.encoding = 'utf-8'
            elif flag ==1:
                res.encoding = 'gbk'

        #Find HTTP title in the page
        pattern = re.compile(r"(?i)<title>.*?</title>")
        if pattern.findall(res.text):
            title_list = pattern.findall(res.text)
            title = title_list[0]
            title = title[7:-8]
        else:
            title = "[!] HTTP title not found."
    except Exception, e:
        title = "[!] Can not connect."
    return title

def search_ip_ports(ip):
    port = ''
    module = ''
    try:
        # Lookup the host
        host = api.host(ip,history=False)
    except shodan.APIError, e:
        if re.search("No information available for that IP.",str(e)):
            print(ip+" | [!] No result.")
            print("--------------------------------------------------------------------------------")
            return
        if re.search("Invalid IP",str(e)):
            print(ip+" | [!] IP invalid.")
            print("--------------------------------------------------------------------------------")
            return

    # Print general info
    print("""{} | {} | {}
""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

    # Print all banners
    for item in host['data']:
        # If module equals HTTP, get the HTTP title
        if re.search("http(s)?", item['_shodan']['module']):
            protocol = re.search("http(s)?", item['_shodan']['module'])
            http_title = " | "+get_http_title(ip, str(item['port']), protocol.group(0))
        else:
            http_title = ""
        try:
            #Print port, module, http_title(if exists)
            print str(item['port'])+" | "+item['_shodan']['module']+http_title.encode("utf-8")

        except UnicodeEncodeError, e:
            http_title = " | "+get_http_title(ip, str(item['port']), protocol.group(0), 1)
            print str(item['port'])+" | "+item['_shodan']['module']+http_title.encode("utf-8")
    print("--------------------------------------------------------------------------------")

def search_ip_list_ports(iplist):
    for ip in iplist:
        time.sleep(1)
        search_ip_ports(ip)
        

def main():
    if len(sys.argv) < 2:
        print("Usage: \n    python ShodanSearch.py \"IPList.txt\"")
        sys.exit()
    ip_list = get_ip_list(sys.argv[1])
    print(ip_list)
    print('[*] Total '+str(len(ip_list))+' IP addresses.')
    print(time.strftime('[*] Search started at %H:%M:%S %a %Y-%m-%d.',time.localtime(time.time())))
    print("--------------------------------------------------------------------------------")
    search_ip_list_ports(ip_list)
    print(time.strftime('[*] Search finished at %H:%M:%S %a %Y-%m-%d.',time.localtime(time.time())))

if __name__ == '__main__':
    main()

