import argparse
import requests
import sys
import json
from bs4 import BeautifulSoup
import re
from colorama import Fore, Back, Style
import csv
import datetime
from termcolor import colored, cprint
import whois
import socket
from parser import HtmlParser
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urljoin
import pyfiglet
import time



def logo():
    ascii_banner = pyfiglet.figlet_format("DOT SCANNER")
    print(ascii_banner)
    print("-" * 50)
    cprint(Fore.YELLOW + "Dotworld Techologies" + Style.RESET_ALL, attrs=['bold'])
    cprint(Fore.BLUE + "https://dotworld.in"+ Style.RESET_ALL, attrs=['bold'])
    cprint(Fore.RED + 'Created By : Anandharaj', attrs=['bold'])
    cprint(Fore.BLACK + 'Twitter    : https://twitter.com/anand_cyb3r', attrs=['bold'])
    print("-" * 50)
    print("")


def selectpath(_path):
    filepath = _path
    #/home/cipher/Documents/library.txt
    with open(filepath) as fp:
        line = fp.readline()
        cnt = 1
        p = []
        q = []
        ree = []
        s = []
        while line:
            a = "{}".format(line.strip())
            line = fp.readline()
            b = a.split('\t')
            global _version, _key
            _key = (b[0])
            _version = (b[1])
            cnt += 1
            cprint(Fore.RED + "Searching: " + _key + "from" + _version + Style.RESET_ALL, attrs=['blink'])
            SEARCHURL = "https://snyk.io/vuln/npm:" + _key + "@" + _version
            r = requests.get(SEARCHURL)
            if r.status_code != 200:
                SEARCHURLL = "https://snyk.io/vuln/search?q=" + _key
                r = requests.get(SEARCHURLL)
                soup = BeautifulSoup(r.content, 'html.parser')
                for a in soup.find_all('a', href=True):
                    n = a['href']
                    vari = ":"
                    va = "/"
                    x = n.partition(vari)[0]
                    y = x.partition(va)[2]
                    z = y.partition(va)[2]
                    h = z.count('SNYK')
                    for i in range(h):
                        if z.startswith('SNYK') == True:
                            SEARCHURLLL = "https://snyk.io/vuln/" + z
                            r = requests.get(SEARCHURLLL)
                            soup = BeautifulSoup(r.content, 'html.parser')
                            for a in soup.find_all('a', href=True):
                                n = a['href']
                                w = soup.find_all("div", class_="cvss-breakdown__score")
                                ww = str(w)
                                if ww.startswith('[<div') == True:
                                    cvs = soup.find_all("div", class_="cvss-breakdown__score")
                                    cvsss = str(cvs)
                                    cvssss = cvsss.split('>')
                                    cvssc= str(cvssss[1]).split('<')
                                    cvss = cvssc[0]
                                else:
                                    cvss = "No CVSS Score for this issue"
                                vari = ":"
                                cwe = "//"
                                x = n.partition(vari)[2]
                                e = x.partition(cwe)[2]
                                if e.startswith('cwe') == True:
                                    print(Style.RESET_ALL)
                                    print(Fore.RED + "Issue found: ",e)
                                    print(Fore.BLUE + "CVSS Score: ", cvss)
                                    print(Style.RESET_ALL)
                                    p.append(_key)
                                    q.append(_version)
                                    ree.append(e)
                                    s.append(cvss[0])
                                elif e.startswith('cve') == True:
                                    print(Style.RESET_ALL)
                                    print(Fore.RED + "Issue found: ",e)
                                    print(Fore.BLUE + "CVSS Score: ", cvss)
                                    print(Style.RESET_ALL)
                                    p.append(_key)
                                    q.append(_version)
                                    ree.append(e)


            else:
                soup = BeautifulSoup(r.content, 'html.parser')
                for a in soup.find_all('a', href=True):
                    n = a['href']
                    vari = ":"
                    x = n.partition(vari)[2]
                    y = x.partition(vari)[2]
                    z = re.findall('\d+', y)
                    if len(z):
                        if len(z[0])>2:
                            c = z[0]

                            SEARCHURLL = "https://snyk.io/vuln/npm:" + _key + ":" + c
                            req = requests.get(SEARCHURLL)
                            if req.status_code != 200:
                                print("Something wrong.")
                            else:
                                soup = BeautifulSoup(req.content, 'html.parser')
                                for a in soup.find_all('a', href=True):
                                    cvs = soup.find_all("div", class_="cvss-breakdown__score")
                                    cvsss = str(cvs)
                                    cvssss = cvsss.split('>')
                                    cvss = str(cvssss[1]).split('<')
                                    n = a['href']
                                    vari = ":"
                                    cwe = "//"
                                    x = n.partition(vari)[2]
                                    e = x.partition(cwe)[2]
                                    if e.startswith('cwe') == True:
                                        print(Style.RESET_ALL)
                                        print(Fore.RED + "Issue found: ",e)
                                        print(Fore.BLUE + "CVSS Score: ", cvss[0])
                                        print(Style.RESET_ALL)
                                        p.append(_key)
                                        q.append(_version)
                                        ree.append(e)
                                        s.append(cvss[0])

        row_list = [["Library","Version","URL", "Cvss Score"],[p,q,ree, s]]
        with open('/home/cipher/Documents/output1.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(row_list)
        print("List of Issues are generated csv file...!")

def search_cve(_cve):
    cprint(Fore.RED + "Searching: " + _cve + Style.RESET_ALL, attrs=['blink'])
    SEARCHURL = "http://cve.circl.lu/api/cve/" + _cve
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        data = json.loads(r.text)
        print(Fore.GREEN + "Summary: " + data['summary'])
        print(Fore.BLUE + "CVSS Score: " + str(data['cvss']))
        print(Style.RESET_ALL)


def list_vendors():
    print("Listing Vendors")
    SEARCHURL = "http://cve.circl.lu/api/browse"
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        print(" ... " + str(r.status_code))
        data = json.loads(r.text)['vendor']
        print("Available Vendors: ")
        for item in data:
            print(item)

def list_vendor_products(_vendor):
    print("Vendor Search: " + _vendor)
    SEARCHURL = "http://cve.circl.lu/api/browse/" + _vendor
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        print(" ... " + str(r.status_code))
        try:
            data = json.loads(r.text)['product']
            print("Available products from " + _vendor)
            for item in data:
                print(item)
        except:
            sys.exit("[!!] Vendor not in list")

def search_key(_key):
    cprint(Fore.RED + "Searching: " + _key + Style.RESET_ALL, attrs=['blink'])
    SEARCHURL = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + _key
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        soup = BeautifulSoup(r.content, 'html.parser')
        for a in soup.find_all('a', href=True):
            n = a['href']
            vari = "="
            x = n.partition(vari)[2]
            print(x)

def search_cve_version(_key, _version):
    cprint(Fore.RED + "Searching: " + _key + _version + Style.RESET_ALL, attrs=['blink'])
    SEARCHURL = "https://snyk.io/vuln/npm:" + _key + "from" + _version
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        soup = BeautifulSoup(r.content, 'html.parser')
        for a in soup.find_all('a', href=True):
            n = a['href']
            vari = ":"
            x = n.partition(vari)[2]
            y = x.partition(vari)[2]
            z = re.findall('\d+', y)
            if len(z):
                if len(z[0])>2:
                    c = z[0]
                    print(c)
        print("If you want full details of issue check google on "+ _key + ":" + c)
        print("1. Enter the issue number for full details: \n2.Quite")
        b = int(input("Enter the options: "))
        if b == 1:
            q = input("Enter the issue number: ")
            crint(Fore.RED + "Searching: "+_key + q + Style.RESET_ALL, attrs=['blink'])
            SEARCHURLL = "https://snyk.io/vuln/npm:" + _key + ":" + q
            req = requests.get(SEARCHURLL)
            if req.status_code != 200:
                sys.exit("Something wrong.")
            else:
                soup = BeautifulSoup(req.content, 'html.parser')
                for a in soup.find_all('a', href=True):
                    n = a['href']
                    vari = ":"
                    cwe = "//"
                    x = n.partition(vari)[2]
                    e = x.partition(cwe)[2]
                    if e.startswith('cwe') == True:
                        print(e)
        elif b == 2:
            print("Quite...")

def show_vendor_product(_vendor, _product):
    cprint(Fore.RED + "Searching: " + _product + " from " + _vendor + Style.RESET_ALL, attrs=['blink'])
    SEARCHURL =  "http://cve.circl.lu/api/search/" + _vendor + "/" + _product
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        jdata = json.loads(r.text)
        for item in jdata:
            print("\nSummary: " + item['summary'])
            print("CVE: " + item['id'])
            print("CVSS: " + str(item['cvss']))

def search_cwe(_cwe):
    cprint(Fore.RED + "Searching: "+ _cwe + Style.RESET_ALL, attrs=['blink'])
    SEARCHURL = "https://www.cvedetails.com/vulnerability-search.php?f=1&cweid=" + _cwe
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        soup = BeautifulSoup(r.content, 'html.parser')
        for a in soup.find_all('a', href=True):
            n = a['href']
            vari = "/"
            m = n.partition(vari)[2]
            o = m.partition(vari)[2]
            p = o.partition(vari)[0]
            if p.startswith('CVE') == True:
                print(p)

def search_cve_date(_year, _month):
    mon = int(_month)
    yr = int(_year)
    months = datetime.date(yr, mon, 1).strftime('%B')
    cprint(Fore.RED + "Searching: " + _year + " : " + months + Style.RESET_ALL, attrs=['blink'])
    SEARCHURL = "https://www.cvedetails.com/vulnerability-list/year-" +_year + "/month-" + _month + "/" + months + ".html"
    r = requests.get(SEARCHURL)
    if r.status_code != 200:
        sys.exit("Something wrong.")
    else:
        soup = BeautifulSoup(r.content, 'html.parser')
        for a in soup.find_all('a', href=True):
            n = a['href']
            vari = "/"
            m = n.partition(vari)[2]
            o = m.partition(vari)[2]
            p = o.partition(vari)[0]
            if p.startswith('CVE') == True:
                print(p)

def whoise_domain(_url):
    cprint(Fore.RED + "Searching: " + _url + Style.RESET_ALL, attrs=['blink'])
    print(whois.whois(_url))

def search_ip(_ip):
    cprint(Fore.RED + "Searching: " + _ip + Style.RESET_ALL, attrs=['blink'])
    print("Ip Address: ", socket.gethostbyname(_ip))

class Crawler(object):

    def __init__(self, seedurl):
        cprint(Fore.RED + "Searching: " + seedurl + Style.RESET_ALL, attrs=['blink'])
        self.seedurl = seedurl
        self.urlseen = set()
        urlparsed = urlparse(seedurl)
        self.domain = urlparsed.netloc

    def gl(self, html):
        hrefs = set()
        parser = HtmlParser(html)
        for href in parser.hrefs:
            u_parse = urlparse(href)
            if u_parse.netloc == '' or u_parse.netloc == self.domain:
                hrefs.add(href)
        return hrefs

    def fetch(self, url):
        try:
            req = Request(url)
            res = urlopen(req)
            return res.read().decode('utf-8', 'ignore')
        except HTTPError as e:
            print('ERROR: %s \t  %s' % (url, e.code))
            return ''
        except URLError as e:
            print('Reason: ', e.reason)
            return ''
    def crawl(self):
        url_frontier = list()
        url_frontier.append(self.seedurl)
        while url_frontier:
            url = url_frontier.pop()
            if url not in self.urlseen:
                html = self.fetch(url)

                if html:
                    print('Crawl: ', url)
                    self.urlseen.add(url)

                for href in self.gl(html):
                    joinlink = urljoin(self.seedurl, href)
                    url_frontier.append(joinlink)
    @property
    def crawled_urls(self):
        self.crawl()
        return self.urlseen
import nmap
def port_scanner(_targeturl):
    nmScan = nmap.PortScanner()
    nmScan.scan(_targeturl, '21-443')
    for host in nmScan.all_hosts():
        print('Host : %s (%s)' % (host, nmScan[host].hostname()))
        print('State : %s' % nmScan[host].state())
        for proto in nmScan[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)
            lport = nmScan[host][proto].keys()
            for port in lport:
                print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))

def __main__():
    parser = argparse.ArgumentParser(description='CIRCL CVE API Search')
    parser.add_argument('--path', '-p', dest='path', help='select a Path for library file to search CWE')
    parser.add_argument('--cve', '-c', dest='cve', help='Search for specific CVE')
    parser.add_argument('--cwe', '-cwe', dest='cwe', help='Search for specific CWE')
    parser.add_argument('--list-vendors', '-l', dest='listvendors', action='store_true', help='List the available Vendors')
    parser.add_argument('--product', '-prct', dest='product', help='Search for a Product')
    parser.add_argument('--keyword', '-k', dest='keywords', help='Search for specific Keyword')
    parser.add_argument('--vendors', '-v', dest='vendor', help='Search for a Vendor')
    parser.add_argument('--verion', '-ver', dest='version', help='Search for this Version')
    parser.add_argument('--year', '-y', dest='year', help='Search for year')
    parser.add_argument('--month', '-m', dest='month', help='Search for month')
    parser.add_argument('--url', '-u', dest='url', help='Whoise lookup a domain')
    parser.add_argument('--urlip', '-uip', dest='urlip', help='Search ip address of domain')
    parser.add_argument('--seedurl', '-su', dest='seedurl', help='Crawal URL')
    parser.add_argument('--targeturl', '-tu', dest='targeturl', help='Crawal URL')
    args = parser.parse_args()
    _path = args.path
    _cve = args.cve
    _listvendors = args.listvendors
    _product = args.product
    _key = args.keywords
    _vendor = args.vendor
    _version = args.version
    _cwe = args.cwe
    _year = args.year
    _month = args.month
    _url = args.url
    _ip = args.urlip
    _seedurl = args.seedurl
    _targeturl = args.targeturl
#main_call
    logo()
    if args.path:
        selectpath(_path)
    elif (args.vendor and args.product):
        show_vendor_product(_vendor, _product)
    elif (args.keywords and args.version):
        search_cve_version(_key, _version)
    elif (args.year and args.month):
        search_cve_date(_year, _month)
    elif args.cve:
        search_cve(_cve)
    elif args.listvendors:
        list_vendors()
    elif (args.vendor and not args.product):
        list_vendor_products(_vendor)
    elif args.keywords:
        search_key(_key)
    elif args.cwe:
        search_cwe(_cwe)
    elif  args.url:
        whoise_domain(_url)
    elif args.urlip:
        search_ip(_ip)
    elif args.seedurl:
        crawler = Crawler(_seedurl)
        for url in crawler.crawled_urls:
            print('>>>', url)
    elif args.targeturl:
        port_scanner(_targeturl)


if __name__ == '__main__':
    __main__()
