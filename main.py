from prometheus_client import Counter, start_http_server
import socket
import struct
import time
from datetime import datetime
from scapy.all import *

recorded_addrs = {}
c = Counter('new_network_hits', 'New Network Hits')

recorded_addrs = {}


def analyze_network(pkt, ips_arr=recorded_addrs):
    """Reads the given file and outputs all new connections

    Keyword arguments:
    path -- (optional) The path to the file to read
    ip_arr -- (optional) The in-memory array that stores all seen connections
    """
    from_ip, from_port, to_ip, to_port = interpret_packet(pkt)
    if from_ip == "":
        return ""

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


def ports_scanned_detector(port_times):
    """Detects if ports are being scanned

    Returns an array of ports scanned, if a scan is detected.
    A scan has been detected if the same from_ip and to_ip are being hit
    but the to_ports are different, and three or more different ports were hit in less than 60 seconds

    Keyword arguments:
    port_times -- An array of objects containing the ports that were hit, and the iso timestamp they were hit
                  For example: {"port": 80, "time": 2022-03-25T22:46:41+0000}
    """
    new_date = datetime.now()
    ports_scanned_in_last_min = []
    for obj in port_times:
        if obj["port"] not in ports_scanned_in_last_min:
            old_date = datetime.fromisoformat(obj["time"])
            date_diff = new_date - old_date
            if date_diff.total_seconds() <= 60:
                ports_scanned_in_last_min.append(obj["port"])
    if len(ports_scanned_in_last_min) >= 3:
        return ports_scanned_in_last_min
    return []


def get_now():
    """Returns the current time in datetime's iso format"""
    return datetime.now().isoformat()


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
    return ips_arr


def block_ip_ufw(from_ip, path="/firewall/user.rules"):
    """
    Adds a block rule in UFW

    Keyword arguments:
    from_ip -- The IP to block
    path -- The path to the user.rules file
    """
    test = "### tuple ### deny any any 0.0.0.0/0 any {} in".format(from_ip)
    test2 = "-A ufw-user-input -s {} -j DROP".format(from_ip)
    match_string = "### RULES ###"
    insert_string = "\n{}\n{}\n".format(test, test2)
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


def interpret_packet(pkt):
    """
    Gets the to and from IP and Port from the packet

    Keyword arguments:
    pkt -- The packet
    """
    from_ip = from_port = to_ip = to_port = ""
    if "IP" in pkt:
        from_ip = pkt["IP"].src
        to_ip = pkt["IP"].dst
    if "TCP" in pkt:
        from_port = pkt["TCP"].sport
        to_port = pkt["TCP"].dport

    return from_ip, from_port, to_ip, to_port


if __name__ == "__main__":
    start_http_server(5000)
    # sniff(prn=analyze_network)
    sniff(filter="tcp and tcp.flags.syn==1 and tcp.flags.ack==0", prn=analyze_network)
