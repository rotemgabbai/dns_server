import psycopg2
from scapy.all import *
import config
from utils.db_utils import get_answer

def ask_dns_server(qtype, qname):
    print(qname)
    print(qtype)
    dns_server_request = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    ans = sr1(dns_server_request, verbose=0)
    return ans

def handle_pkt(packet):
    if DNS in packet:
        if packet[DNS].qr == 0:
            qname = packet[DNS].qd.qname
            qname_decode = qname.decode().rstrip('.')
            qtype = packet[DNS].qd.qtype
            if qtype == 1:
                pkt_type = 'A'
            elif qtype == 12:
                pkt_type = 'PTR'
            else:
                return
            ans = get_answer(pkt_type, qname_decode)
            if ans:
                typ, name, value, ttl = ans
                dns_ans = DNSRR(rrname=qname, type=qtype, ttl=ttl, rdata=value)
                dns_packet = IP(dst=packet[IP].src, src=packet[IP].dst)/ \
                             UDP(dport=packet[UDP].sport, sport=5353)/ \
                             DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, ancount=1, an=dns_ans)
            else:
                print('Asking 8.8.8.8 server...')
                dns_server_ans = ask_dns_server(pkt_type, qname_decode)
                
                if dns_server_ans:
                    dns_packet = IP(dst=packet[IP].src, src=packet[IP].dst)/ \
                                 UDP(dport=packet[UDP].sport, sport=53)/ \
                                 dns_server_ans[DNS]
                else:
                    dns_packet = IP(dst=packet[IP].src, src=packet[IP].dst)/ \
                                UDP(dport=packet[UDP].sport, sport=5353)/ \
                                DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, rcode=3)
                    print('no such name')
            send(dns_packet)     

def main():
    print('The server is listening to port 5353...')
    sniff(iface="\\Device\\NPF_Loopback", filter='udp port 5353', prn=handle_pkt)

if __name__ == "__main__":
    main()