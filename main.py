import socket
import struct
import sched, time

recorded_addrs = []

def main():
    while (True):
        analyze_file()
        time.sleep(10)

def analyze_file(path="/proc/net/tcp.txt", ips_arr=recorded_addrs):
    """Reads the given file and outputs all new connections

    Keyword arguments:
    path -- (optional) The path to the file to read
    ip_arr -- (optional) The in-memory array that stores all seen connections
    """

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
    """Parses a line from /proc/net/tcp.txt and returns the local address and the remote address

    The expected format is described here: https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
    
    Keyword arguments:
    line -- the string that will be parsed
    """
    arr = line.strip().split()
    local_addr = arr[1]
    remote_addr = arr[2]

    return local_addr, remote_addr

def translate_addr_from_hex(hex_addr):
    """Translates an IP address from hex to a human readable format

    For example: 0100007F:0050 == 127.0.0.1:80 and E10FA20A:01BB == 10.162.15.225:443
    
    Keyword arguments:
    hex_addr -- the hex string in the format ip:port
    """
    hex_ip, hex_port = hex_addr.split(':')
    ip = int(hex_ip, 16)
    ip = socket.inet_ntoa(struct.pack("<L", ip))

    port = str(int(hex_port, 16))

    return "{}:{}".format(ip, port)

def seen_before(from_ip, to_ip, ips_arr=recorded_addrs):
    """Determines if we have seen this to/from ip address combination before.
    
    Keyword arguments:
    from_ip -- The ip address that the network traffic is coming from
    to_ip -- The ip address that the network traffic is targeting
    ips_arr -- (optional) The in-memory array that stores what has been seen before
    """
    lookup_str = "{} -> {}".format(from_ip, to_ip)
    return lookup_str in ips_arr

if __name__ == "__main__":
    main()