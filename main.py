from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8

def checksum(source: bytes):
    csum = 0
    countTo = (len(source) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = source[count+1] * 256 + source[count]
        csum = (csum + thisVal) & 0xffffffff
        count += 2

    if countTo < len(source):
        csum = (csum + source[-1]) & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer = ~csum & 0xffff
    # swap bytes
    answer = (answer >> 8) | ((answer << 8) & 0xff00)
    return answer

def receiveOnePing(mySocket, ID, timeout, destAddr):
    timeLeft = timeout
    while 1:
        startedSelect = time.time()
        whatReady = select.select([mySocket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []:  # Timeout
            return "Request timed out."

        timeReceived = time.time()
        recPacket, addr = mySocket.recvfrom(1024)

        # Fill in start
        ipHeader = recPacket[:20]
        iph = struct.unpack("!BBHHHBBH4s4s", ipHeader)
        ihl = (iph[0] & 0x0F) * 4               # IP header length in bytes
        ttl = iph[5]

        # Fetch the ICMP header from the IP packet
        icmpHeader = recPacket[ihl:ihl+8]
        icmpType, code, myChecksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

        if icmpType != 0 or packetID != ID:
            timeLeft = timeLeft - howLongInSelect
            if timeLeft <= 0:
                return "Request timed out."
            continue
        
        timeSent = struct.unpack("d", recPacket[ihl+8:ihl+16])[0]
        rtt_ms = (timeReceived - timeSent) * 1000.0
        return f"Reply from {destAddr}: seq={sequence} ttl={ttl} rtt={rtt_ms:.3f} ms"
        # Fill in end

def sendOnePing(mySocket, destAddr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    myChecksum = 0
    # struct -- Interpret strings as packed binary data
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    # Calculate the checksum on the data and the dummy header.
    myChecksum = checksum(header + data)
    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    packet = header + data
    mySocket.sendto(packet, (destAddr, 1))  # AF_INET address must be tuple, not str

def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    # SOCK_RAW requires admin/root privileges
    mySocket = socket(AF_INET, SOCK_RAW, icmp)
    myID = os.getpid() & 0xFFFF
    sendOnePing(mySocket, destAddr, myID)
    delay = receiveOnePing(mySocket, myID, timeout, destAddr)
    mySocket.close()
    return delay

def ping(host, timeout=1):
    dest = gethostbyname(host)
    print("Pinging " + dest + " using Python:\n")
    while 1:
        delay = doOnePing(dest, timeout)
        print(delay)
        time.sleep(1)

if __name__ == "__main__":
    # ping("127.0.0.1")           #Test (localhost)
    # ping("www.berkeley.edu")    #North America
    # ping("www.ripe.net")        #Europe
    # ping("www.keio.ac.jp")      #Asia (Japan)
    ping("www.ufrj.br")          #South America (Brazil)
