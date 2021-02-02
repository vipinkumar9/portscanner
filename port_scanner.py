import socket
import argparse
import struct
import random
import sys
import itertools
import threading
import time
from IPy import IP


def arg():
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--host', help='Enter host', required=True)
    parser.add_argument('-p', '--port', help='Enter port range e.g 0-100')
    parser.add_argument('-sN', '--normal', help='Normal Scan')
    parser.add_argument('-sT', '--tcp', help='TCP Scan')
    parser.add_argument('-sU', '--udp', help='UDP Scan')
    return parser.parse_args()


def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rScanning  ' + c)
        sys.stdout.flush()
        time.sleep(0.1)

    sys.stdout.write('\rFinished!     \n')


class Scanner:
    def __init__(self, ip, startPort, endPort):
        self.url = "www.google.com"
        self.ip = str(socket.gethostbyname(ip))
        self.startPort = startPort
        self.endPort = endPort

    def tcp_scan(self, i):
        """ Creates a TCP socket and attempts to connect via supplied ports """

        try:
            # Create a new socket
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Print if the port is open
            if not tcp.connect_ex((self.ip, i)):
                print('\n[+] %s:%d/TCP Open' % (self.ip, i))
                tcp.close()

        except Exception:
            pass

    def normal_scan(self, i):

        sock = socket.socket()
        try:
            sock.connect((self.ip, i))
            print(f"\n[+] {self.ip}:{i} is OPEN ")
        except:
            pass

    def _build_packet(self):
        randint = random.randint(0, 65535)
        packet = struct.pack(">H", randint)  # Query Ids (Just 1 for now)
        packet += struct.pack(">H", 0x0100)  # Flags
        packet += struct.pack(">H", 1)  # Questions
        packet += struct.pack(">H", 0)  # Answers
        packet += struct.pack(">H", 0)  # Authorities
        packet += struct.pack(">H", 0)  # Additional
        split_url = self.url.split(".")
        for part in split_url:
            packet += struct.pack("B", len(part))
            for s in part:
                packet += struct.pack('c', s.encode())
        packet += struct.pack("B", 0)  # End of String
        packet += struct.pack(">H", 1)  # Query Type
        packet += struct.pack(">H", 1)  # Query Class
        return packet

    def udp_scan(self, i):
        message = "This is a message, hello!"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            sent = sock.sendto(
                bytes(message.encode("UTF-8")), (self.ip, i))
            sock.settimeout(6.0)

            # receive response
            data = sock.recvfrom(1)

            print('\n[+] %s:%d/UDP Open' % (self.ip, i))

        except socket.timeout as err:
            pass

        finally:
            sock.close()


args = arg()
startPort, endPort = int(args.port.split("-")[0]), int(args.port.split("-")[1])
scanner = Scanner(args.host, startPort, endPort)

if args.normal is not None:
    done = False
    t = threading.Thread(target=animate)
    t.start()
    t1 = time.time()
    threads = [threading.Thread(target=scanner.normal_scan(c))
               for c in range(startPort, endPort+1)]

    for thread in threads:
        thread.start()
    t2 = time.time()

    done = True
    time.sleep(1)
    print("\nTime taken : " + str(round(t2-t1, 2)) + " seconds")


elif args.tcp is not None:
    done = False
    t = threading.Thread(target=animate)
    t.start()
    t1 = time.time()
    threads = [threading.Thread(target=scanner.tcp_scan(d))
               for d in range(startPort, endPort+1)]

    for thread in threads:
        thread.start()
    done = True
    time.sleep(1)
    t2 = time.time()
    print("\nTime taken : " + str(round(t2-t1, 2)) + " seconds")


elif args.udp is not None:
    done = False
    t = threading.Thread(target=animate)
    t.start()
    t1 = time.time()
    threads = [threading.Thread(target=scanner.udp_scan(f))
               for f in range(startPort, endPort+1)]

    for thread in threads:
        thread.start()
    t1 = time.time()
    done = True
    time.sleep(1)

    print("\nTime taken : " + str(round(t2-t1, 2)) + " seconds")


else:
    print('Give at least one search method')
