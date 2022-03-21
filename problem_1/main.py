import socket
import struct

recorded_addrs = []

def read_file(path="/proc/net/tcp.txt", ips_arr=recorded_addrs):
    try:
        f = open(path, "r")
        for line in f:
           # Skip header line, if it exists
           if "local_address" in line:
               continue
           # Get both the "from" and "to" ips and their ports
           from_ip, to_ip = parse_line(line)
           # Translate them from hex
           from_ip = translate_addr_from_hex(from_ip)
           to_ip = translate_addr_from_hex(to_ip)
           fmt_str = "{} -> {}".format(from_ip, to_ip)
           # Check if they're new
           if fmt_str not in ips_arr:
                # Save for future reference
                ips_arr.append(fmt_str) 
                # Print it out
                print("New connection: {}".format(fmt_str))
        return ips_arr
    except IOError:
        print("Failed to open/read from file '%s'" % (path))

def parse_line(line):
    arr = line.strip().split()
    local_addr = arr[1]
    remote_addr = arr[2]

    return local_addr, remote_addr

def translate_addr_from_hex(hex_addr):
    hex_ip, hex_port = hex_addr.split(':')
    ip = int(hex_ip, 16)
    ip = socket.inet_ntoa(struct.pack("<L", ip))

    port = str(int(hex_port, 16))

    return "{}:{}".format(ip, port)

def seen_before(from_ip, to_ip, ips_arr=recorded_addrs):
    lookup_str = "{} -> {}".format(from_ip, to_ip)
    return lookup_str in ips_arr