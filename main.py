from prometheus_client import Counter, start_http_server
import socket
import struct
import time
import datetime

recorded_addrs = {}
c = Counter('new_network_hits', 'New Network Hits')

def main():
    while (True):
        analyze_file()
        time.sleep(10)

def analyze_file(path="./tcp", ips_arr=recorded_addrs):
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
            from_ip, from_port = translate_addr_from_hex(from_ip)
            to_ip, to_port = translate_addr_from_hex(to_ip)

            # Port scan
            fmt_str = "{} -> {}".format(from_ip, to_ip)
            for ip in ips_arr:    
                if fmt_str == ip:
                    scanned_ports = ports_scanned_detector(ips_arr[fmt_str])
                    if scanned_ports:
                        block_ip_ufw(from_ip)
                        print("Port scan detected: {} -> {} on ports {}".format(from_ip, to_ip, scanned_ports))
                    # Save connection for future reference
                    new_connection(ips_arr, from_ip, from_port, to_ip, to_port)
                    break
                else:
                    # Save connection for future reference
                    new_connection(ips_arr, from_ip, from_port, to_ip, to_port)
                    break
            else:
                # Save connection for future reference
                new_connection(ips_arr, from_ip, from_port, to_ip, to_port)
            return ips_arr
    except IOError:
        print("Failed to open/read from file '%s'" % (path))

def parse_line(line):
    """Parses a line from /proc/net/tcp and returns the local address and the remote address

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

    return ip, port

def ports_scanned_detector(port_times):
    """Detects if ports are being scanned

    Returns an array of ports scanned, if a scan is detected. 
    A scan has been detected if the same from_ip and to_ip are being hit
    but the to_ports are different, and three or more different ports were hit in less than 60 seconds
    
    Keyword arguments:
    port_times -- An array of objects containing the ports that were hit, and the iso timestamp they were hit
                  For example: {"port": 80, "time": 2022-03-25T22:46:41+0000}
    """
    new_date = datetime.datetime.now()
    ports_scanned_in_last_min = []
    for obj in port_times:
        if obj["port"] not in ports_scanned_in_last_min:
            old_date = datetime.datetime.fromisoformat(obj["time"])
            date_diff = new_date - old_date
            if date_diff.total_seconds() <= 60:
                ports_scanned_in_last_min.append(obj["port"])
    if len(ports_scanned_in_last_min) >= 3:
        return ports_scanned_in_last_min
    return []

def get_now():
    """Returns the current time in datetime's iso format"""
    return datetime.datetime.now().isoformat()

def new_connection(ips_arr, from_ip, from_port, to_ip, to_port):
    """Prints, saves, and counts a new connection

    This will print out a new connection "New connection: 1.1.1.1:80 -> 2.2.2.2:80"
    This will also save the new connection into ips_arr
    This will also count the new connection for Prometheus metrics

    Keyword arguments:
    ips_arr -- The place to store all new connections
    from_ip -- The IP address where the connection is coming from
    from_port -- The port where the connection is coming from
    to_ip -- The IP address where the connection is going to
    to_port -- The port where the connection is going to
    """
    fmt_str = "{} -> {}".format(from_ip, to_ip)
    
    if fmt_str not in ips_arr:
        ips_arr[fmt_str] = []
    ips_arr[fmt_str].append({"port": to_port, "time": get_now()})
    print("New connection: {}:{} -> {}:{}".format(from_ip, from_port, to_ip, to_port))
    c.inc()

def block_ip_ufw(from_ip, path="/firewall/user.rules"):
    """
    Adds a block rule in UFW
    """
    match_string = "### RULES ###"
    insert_string = """### tuple ### deny any any 0.0.0.0/0 any ${from_ip} in
-A ufw-user-input -s ${from_ip} -j DROP"""
    with open(path, 'r+') as fd:
        contents = fd.readlines()
        if match_string in contents[-1]:
            contents.append(insert_string)
        else:
            for index, line in enumerate(contents):
                if match_string in line and insert_string not in contents[index + 1]:
                    contents.insert(index + 1, insert_string)
                    break
    fd.seek(0)
    fd.writelines(contents)
    print(from_ip)

if __name__ == "__main__":
    start_http_server(5000)
    main()