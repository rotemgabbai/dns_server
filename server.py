from typing import Optional, Tuple
from utils.db_utils import get_answer
from scapy.all import *

def ask_dns_server(qtype: str, qname: str) -> Optional[Packet]:
    """
    Ask an external DNS server 8.8.8.8

    Args: qtype: Record type 'A' or 'PTR'
          qname: Record name
    Output:
        Scapy packet of the response or None if there is no response
    """
    dns_server_request = IP(dst='8.8.8.8') / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    ans = sr1(dns_server_request, verbose=0)
    return ans

def build_dns_response(packet: Packet, dns_server_ans: Optional[Packet], local_ans: Optional[Tuple], qtype: int) -> Packet:
    """
    Build the DNS response based on the local response or the external server response

    Args: packet: The query packet
          dns_server_ans: the response of the external dns server 
          local_ans: the response of the local dns server if there is one
          qtype: record type
    Output: 
        Scapy packet represent the DNS response
    """
    ip_layer_ans = IP(dst=packet[IP].src, src=packet[IP].dst)
    udp_layer_ans = UDP(dport=packet[UDP].sport, sport=5353)

    if local_ans:
        _type, _name, value, ttl = local_ans
        dns_layer_ans = DNSRR(rrname=packet[DNS].qd.qname, type=qtype, ttl=ttl, rdata=value)
    elif dns_server_ans and DNS in dns_server_ans and dns_server_ans[DNS].ancount > 0:
        dns_layer_ans = dns_server_ans[DNS]
    else:
        dns_layer_ans = DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd, rcode=3)
    
    return ip_layer_ans / udp_layer_ans / dns_layer_ans

def handle_pkt(packet: Packet) -> None:
    """
    Handle the query packet, 
    if there is an answer from the local DNS server, send it 
    else, ask from the external dns server

    Args: packet: The query packet
    Output: The function doesn't return nothing, just send the response packet
    """
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
            local_ans = get_answer(pkt_type, qname_decode)
            dns_server_ans = None

            if not local_ans:
                print('Asking 8.8.8.8 server...')
                dns_server_ans = ask_dns_server(pkt_type, qname)
            
            response_packet = build_dns_response(packet, dns_server_ans, local_ans, qtype)
            send(response_packet)
            
def main() -> None:
    """
    Starts the DNS server to sniff port 5353
    """
    print('The server is listening to port 5353...')
    sniff(iface="\\Device\\NPF_Loopback", filter='udp port 5353', prn=handle_pkt)

if __name__ == "__main__":
    main()