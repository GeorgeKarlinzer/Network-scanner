from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import ping3
import netifaces as ni

def test_port_number(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((host, port))
            return True
        except:
            return False


def ping(ip):
    try:
        res = ping3.ping(ip, timeout=1)
        return not isinstance(res, bool) and isinstance(res, float)
    except:
        return False


def port_scan(host, ports):
    print(f'Scanning {host}...')
    with ThreadPoolExecutor(len(ports)) as executor:
        results = executor.map(test_port_number, [host]*len(ports), ports)
        for port,is_open in zip(ports,results):
            if is_open:
                print(f'> {host}:{port} open')


def ip_scan(ip_pool):
    print('Scanning ip addresses...')
    ip_list = list()
    with ThreadPoolExecutor(len(ip_pool)) as exeuctor:
        results = exeuctor.map(ping, ip_pool)
        for ip, is_exist in zip(ip_pool, results):
            if is_exist:
                ip_list.append(ip)
    return ip_list


def ip_to_number(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def number_to_ip(num):
    return socket.inet_ntoa(struct.pack('!L', num))


if __name__ == '__main__':
    # if len(sys.argv) != 2:
    #     print('There must be only one argument denoting the interface')
    #     exit(1)

    interface = '{BC67EF7D-D137-4A90-94CE-0AFB3F376AAB}'#sys.argv[1]
    myIp = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    mask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
    broadcast = ni.ifaddresses(interface)[ni.AF_INET][0]['broadcast']
    pool_size = ip_to_number('255.255.255.255') - ip_to_number(mask) - 1

    ip_pool = [number_to_ip(ip_to_number(broadcast) - i - 1) for i in range(pool_size)]

    ip_list = ip_scan(ip_pool)

    print('Ip addresses in the subnetwork: ', ip_list)

    for ip in ip_list:
        port_scan(ip, range(1024))
