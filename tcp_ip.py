#!/bin/python3
import socket
from random import randrange


s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) #socket.IPPROTO_TCP for TCP
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) #we are assigning the IP

soucre_ip='192.168.242.133'  #change
destination_ip='192.168.1.1' #change

source_port = '3030'
#-------check sum-----

def chkk(values):
	sum=0
	for i in values:
		x=bin(int(i,16))[2:].zfill(16) #ignore this only for representaion in binary
		sum+=int(i,16)
		print("\n","0x"+i,x," --> ","sum :",hex(sum))
	#- Removing Carryover 15912 , we need it in range FFFF #Do it in binary to understand carryover
	#- print(sum,0xFFFF)
	if sum > 0xFFFF: #- if sum value is greater then 0xFFFF then slice the carry
		carry=hex(sum)[2:3] #0x15912 --> slice get 0x[1]5912
		
	#- print(carry)
	sum=hex(sum)[3:]# 0x15912 --> 5912 in hex
	
	sum=int(sum,16) + int(carry,16)#- convert to int base 16 (HEX) and add carryover
	print(hex(sum),carry) #print Hex and carry
	#- negagtion-- total 0xFFFF as 16 bit
	sum=0xFFFF - sum #0xFFFF-sum
	sum=format(sum,'04x')
	print('\tchecksum :',sum+"\n")
	return sum # value 0000 formate


def iptohex(ip):
	#- let ip = 192.168.1.1
	first='' #- 192.168 --> 16 bit
	second=''#- 1.1 --> 16 bit
	
	for index,value in enumerate(map(int,ip.split("."))): #- map will change the type from string to int
		#- index start from 0 -> 0,1,2,3
		if index <2:
			first+=format(value,'02x') #format always fill remaing with zero upto 2 values, 0x1 --> 01, x for converting to hex.
		else:
			second+=format(value,'02x')
	#returns hex values of ['192168','11']
	return first,second

#-------------IP-----------
version='4' #verion and ihl makes 1 byte, So don't add 0's to it foor checksum
ihl='5'
typeOfServices='00'
TotalLength='0028' #length of packet in bytes 10 x 4=40 --hex--> 28
Identification='abcd'#random hex value, 16 bit
#- as flag+fragment is 3 & 13 bits so we will can write them combine 
Flags='00'
FragmentOffset='00'
ttl='40'
protocol='06'
#- zero in calculation.
ipChecksum='0000'
sourceIP=iptohex(soucre_ip)
destIP=iptohex(destination_ip)
#----List of Varibales of IP Checksums----
#- version + ihl + typeOfServices because the packet is divided into 16 bits. if it was to be divided in 8 bits then version and ihl would be seperated.Follow rules.
#- See packet format for details

#- you can also do the same by dividing the sum of all values and then make their 16 bit chunks.
ip_checksum=[version+ihl+typeOfServices, TotalLength, Identification,Flags+FragmentOffset,ttl+protocol,ipChecksum,sourceIP[0],sourceIP[1],destIP[0],destIP[1]]

ip_header=version+ihl+ typeOfServices+ TotalLength+ Identification+ Flags+ FragmentOffset+ ttl+ protocol+ chkk(ip_checksum)+sourceIP[0]+sourceIP[1]+destIP[0]+destIP[1]
print(ip_header)
ip_hexbytes=bytearray.fromhex(ip_header)

#-----TCP------------------------------
sourcePort=source_port	#16 bit
destPort='0050'      		#16 bit
seqNumber='00000000' 		#32 bit
ackNumber='00000000' 		#32 bit
#dataOffset='5' # min=5 ,max value 15 in decimal(the size of the TCP header in 32-bit words)

#- Normally minimum tcplength is 20 as in our case.
#- TCP length (including the data part,if any) in byte. #we have no data field.
tcplength='0014' #- 5 x 4= 20 bytes --hex-> 0014

#reserved='00'

#flags_1='02'#syn on 000000010 --hex--> 02
t_drf='5002' #combine of (dataoffset,reserved,flag) 16 bit
windowsize='7110' #(flow) here random //window size= bandwidth(mbits comnnects) x delay(ms)//you can get it from 
tcpchecksum='0000'#if wrong will not work
urgentPointer='0000'

tcp_checksum=[protocol,sourceIP[0],sourceIP[1],destIP[0],destIP[1],tcplength,sourcePort,destPort,seqNumber,ackNumber,t_drf,windowsize,tcpchecksum,urgentPointer]
tcp_header=sourcePort + destPort + seqNumber + ackNumber +t_drf+ windowsize+ chkk(tcp_checksum) + urgentPointer
#- bytearray.fromhex(hexstring)-- converts the hex string to bytearray YOU CAN USE encode() also.
tcp_hexbytes=bytearray.fromhex(tcp_header)

print("----IP header & bytes----")
print(f"IP Header : {ip_header}")
print(f"IP Bytes : {ip_hexbytes}\n")

print("----TCP header & bytes----")
print(f"TCP Header : {tcp_header}")
print(f"TCP Bytes : {tcp_hexbytes}\n")

packet=ip_hexbytes+tcp_hexbytes
print("----Packet Sent----")
#- ip_header+tcp_header -->packet hex string
packet_hex=ip_header+tcp_header
print(f"Packet : {packet_hex}")
print(f"Packet bytes: {packet}")
#slice the flag hex from hex string then convert to binary to see the difference
print(f"TCP flag : {format(int(packet_hex[66:68],16),'09b')} \n")
s.sendto(packet, (destination_ip,0))

print("----Packet Received----")
received=s.recv(1024)
received_hex=received.hex()
print(f"Packet : {received_hex}")
print(f"Received Bytes: {received}")
#slice the flag hex from hex string then convert to binary to see the difference
print(f"TCP flags : {format(int(received_hex[66:68],16),'09b')}")



