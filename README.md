# tcp_ip
Art of Manually Crafting Packets (TCP/IP)

**(UPDATED)**

Must read these articles to understand it.
1. [What is TCP/IP ? Explained in detail.](https://medium.com/@4yub1k/what-is-tcp-ip-explained-in-detail-efc57758115e)
2. [Art of Manually Crafting Packets (TCP/IP).](https://medium.com/@4yub1k/art-of-manually-crafting-packets-tcp-ip-175a85ca808c)


## Usage:
_Use in linux environment._

Run the script
```
python3 tcp_ip.py -h
```
```
TCP/IP Crafting : GitHub @4yub1k

optional arguments:
  -h, --help        show this help message and exit
  -s , --srcip      Source Ip address.
  -sp , --srcport   Source port.
  -d , --dstip      Destination Ip address.
  -dp , --dstport   Destination port.
  -t , --timeout    Wait for response.(Default=5 secs)
```
Example:
```
python3 tcp_ip.py -s=192.168.0.16 -sp=12333 -d=192.168.0.1 -dp=80 -t=2
```
__Sample Blue Print Of Packet :__

![ip](https://user-images.githubusercontent.com/45902447/147408122-b0c87a93-dcf8-422d-95b9-442dc8d8e949.jpg)

## IP Checksum:
![ip](https://github.com/4yub1k/tcp_ip/assets/45902447/c9afff17-829c-4645-9813-4792c330fcef)

## TCP Checksum:
![tcp](https://github.com/4yub1k/tcp_ip/assets/45902447/c119a9d9-7091-45a5-abd6-c6a04fe7f687)

## Output:
![final](https://github.com/4yub1k/tcp_ip/assets/45902447/9f0d621e-0cec-4a4a-a986-7e8994152aae)



