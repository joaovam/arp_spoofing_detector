from scapy.all import sniff

IP_MAC_Map = {}

def processPacket(packet):
    src_IP = packet['ARP'].src
    src_MAC = packet['Ether'].src
    if src_MAC in IP_MAC_Map.keys():
        if IP_MAC_Map[src_MAC] != src_IP:
            try:
                old_IP = IP_MAC_Map[src_MAC]
            except:
                old_IP = "unknown"

            return f"\nPossible ARP Attack detected\n Machine {old_IP} may be pretending to be {src_IP}"
    else:
        IP_MAC_Map[src_MAC] = src_IP


sniff(count=0, filter="arp", store=0, prn = processPacket)