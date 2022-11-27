from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import ping3
import netifaces as ni
import sys

# Try to connect with host and port
def test_port_number(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((host, port))
            return True
        except:
            return False


# Try to ping host
def ping(ip):
    try:
        res = ping3.ping(ip, timeout=1)
        return not isinstance(res, bool) and isinstance(res, float)
    except:
        return False


def port_scan(host, ports):
    print(f'Scanning {host}...')
    # Create threads for every scanned port
    with ThreadPoolExecutor(len(ports)) as executor:
        results = executor.map(test_port_number, [host]*len(ports), ports)
        for port,is_open in zip(ports,results):
            if is_open:
                print(f'> {host}:{port} open')


def ip_scan(ip_pool):
    print('Scanning ip addresses...')
    # Create threads for every scanned ip
    ip_list = list()
    with ThreadPoolExecutor(len(ip_pool)) as exeuctor:
        results = exeuctor.map(ping, ip_pool)
        for ip, is_exist in zip(ip_pool, results):
            if is_exist:
                ip_list.append(ip)
    return ip_list


# Convert ip address to long number
def ip_to_number(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


# Convert long number to ip
def number_to_ip(num):
    return socket.inet_ntoa(struct.pack('!L', num))


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('There must be argument denoting the interface (string) and port range(number of ports from 0)')
        exit(1)

    # First argument means scanned interface
    interface = sys.argv[1]
    # Second argument means port range
    port_range = int(sys.argv[2])
    if port_range < 1:
        print('Port range cannot be smoller than one')
        exit(1)

    # Get mask and broadcast address of interface
    mask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
    broadcast = ni.ifaddresses(interface)[ni.AF_INET][0]['broadcast']
    pool_size = ip_to_number('255.255.255.255') - ip_to_number(mask) - 1

    # Create pool of ip addresses of subnetwork
    ip_pool = [number_to_ip(ip_to_number(broadcast) - i - 1) for i in range(pool_size)]

    # Get all hosts of subnetwork
    ip_list = ip_scan(ip_pool)

    print('Ip addresses in the subnetwork: ', ip_list)

    # Get opened ports per host
    for ip in ip_list:
        port_scan(ip, range(port_range))
