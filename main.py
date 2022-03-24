import socket
import struct
import time
import datetime

recorded_addrs = {}

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
            from_ip, from_port = translate_addr_from_hex(from_ip)
            from_ip_port = "{}:{}".format(from_ip, from_port)
            to_ip, to_port = translate_addr_from_hex(to_ip)
            to_ip_port = "{}:{}".format(to_ip, to_port)

            # Check if they're new
            
            # idea = {"1.1.1.1 -> 2.2.2.2": [{"port": "80", "time":"1:30pm"}]}
            # Port scan
            fmt_str = "{} -> {}".format(from_ip, to_ip)
            for ip in ips_arr:    
                if fmt_str == ip:
                    scanned_ports = ports_scanned_detector(ips_arr[fmt_str])
                    if scanned_ports:
                        print("Port scan detected: {} -> {} on ports {}".format(from_ip, to_ip, scanned_ports))
                    
                    # Add into dict for future reference
                    ips_arr[fmt_str].append({"port": to_port, "time": get_now()})
                    print("New connection: {} -> {}".format(from_ip_port, to_ip_port))
                    break
                else:
                    # Add into dict for future reference
                    ips_arr[fmt_str] = [{"port": to_port, "time": get_now()}]
                    print("New connection: {} -> {}".format(from_ip_port, to_ip_port))
                    break
            else:
                # Add into dict for future reference
                ips_arr[fmt_str] = [{"port": to_port, "time": get_now()}]
                print("New connection: {} -> {}".format(from_ip_port, to_ip_port))
                    

                # print(ips_arr)
                # print(from_ip)
                # if from_ip not in ips_arr and to_ip not in ips_arr[from_ip]["ips"]:
                #     # Save for future reference
                #     if from_ip not in ips_arr:
                #         ips_arr.append(from_ip)
                #     ips_arr[from_ip].append({to_ip})
                #     # Print it out
                #     print("New connection: {} -> {}".format(from_ip, to_ip))
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

    return ip, port

def ports_scanned_detector(port_times):
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
    return datetime.datetime.now().isoformat()

    # print(port_times)

if __name__ == "__main__":
    main()