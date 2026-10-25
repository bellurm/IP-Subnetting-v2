"""IPv4 subnet calculator with CIDR and contiguous dotted-netmask input."""
import ipaddress
from abc import ABC, abstractmethod

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def binary(address):
    return '.'.join(f'{int(octet):08b}' for octet in str(address).split('.'))

class IPSubnetting(ABC):
    def __init__(self, ip, prefix):
        self.ip = str(ipaddress.IPv4Address(ip))
        self.network = ipaddress.IPv4Network(f'{self.ip}/{prefix}', strict=False)

    @abstractmethod
    def find_subnet(self):
        """Return the dotted decimal netmask."""

    def decimal_to_binary(self):
        return binary(self.ip)

    def mask_to_binary(self):
        return binary(self.network.netmask)

    def find_network_and_hosts(self):
        total = self.network.num_addresses
        usable = total if self.network.prefixlen >= 31 else total - 2
        return f'Networks: 1, Addresses: {total}, Hosts: {usable}\n'

    def color_binary_string(self, binary_string, mask_string):
        return [''.join((Color.GREEN if mask == '1' else Color.RED) + bit + Color.RESET
                        for bit, mask in zip(bits, masks))
                for bits, masks in zip(binary_string.split('.'), mask_string.split('.'))]

    def color_decimal_string(self, decimal_string, mask_string):
        # Decimal digits do not correspond to network/host bits.
        return [(Color.GREEN if mask == '255' else Color.RED if mask == '0' else Color.YELLOW)
                + octet + Color.RESET
                for octet, mask in zip(decimal_string.split('.'), mask_string.split('.'))]

    def find_network_and_hosts_visually(self):
        mask = self.mask_to_binary()
        return (self.color_binary_string(mask, mask),
                self.color_binary_string(self.decimal_to_binary(), mask),
                self.color_decimal_string(self.ip, self.find_subnet()))

    def extract_network_and_host_parts(self, colored_segments):
        """Split bit strings at the CIDR boundary, discarding ANSI colors."""
        import re
        bits = re.sub(r'\x1b\[[0-9;]*m', '', ''.join(colored_segments)).replace('.', '')
        return bits[:self.network.prefixlen], bits[self.network.prefixlen:]

    def find_network_and_host_addresses(self):
        return self.extract_network_and_host_parts(self.decimal_to_binary().split('.'))

    def find_network_address(self):
        return binary(self.network.network_address)

    def find_network_address_decimal(self):
        return str(self.network.network_address)

    def find_broadcast_address(self):
        return str(self.network.broadcast_address)

    def find_usable_ip_range(self):
        if self.network.prefixlen >= 31:
            return str(self.network.network_address), str(self.network.broadcast_address)
        return str(self.network.network_address + 1), str(self.network.broadcast_address - 1)

class CIDR(IPSubnetting):
    def __init__(self, ip, cidr):
        if not validate_cidr(str(cidr)):
            raise ValueError('CIDR must be between 0 and 32')
        self.cidr = str(int(cidr))
        super().__init__(ip, self.cidr)

    def find_subnet(self):
        return str(self.network.netmask)

class SubnetMask(IPSubnetting):
    def __init__(self, ip, subnetmask):
        mask = ipaddress.IPv4Address(subnetmask)
        mask_bits = f'{int(mask):032b}'
        if '01' in mask_bits:
            raise ValueError('Subnet mask must contain contiguous leading ones')
        super().__init__(ip, mask_bits.count('1'))
        self.subnetmask = str(mask)

    def find_subnet(self):
        return self.subnetmask

class IPSubnettingFactory:
    @staticmethod
    def create_ip_subnetting(ip_input):
        try:
            value = ip_input.strip()
            if '/' in value:
                ip, cidr = value.split('/')
                return CIDR(ip.strip(), cidr.strip())
            ip, mask = value.split()
            return SubnetMask(ip, mask)
        except (ValueError, TypeError):
            print(f'{Color.RED}[ERROR] Invalid IPv4 address, CIDR or subnet mask.{Color.RESET}')
            return None

def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except (ValueError, TypeError):
        return False

def validate_cidr(cidr):
    return isinstance(cidr, str) and cidr.isascii() and cidr.isdigit() and 0 <= int(cidr) <= 32

def main():
    try:
        value = input('IPv4/CIDR or IPv4 netmask: ')
    except (EOFError, KeyboardInterrupt):
        return 130
    method = IPSubnettingFactory.create_ip_subnetting(value)
    if method is None:
        return 2
    print(f'IP (binary): {method.decimal_to_binary()}')
    print(f'Subnet mask: {method.find_subnet()}')
    print('Green: network bits; red: host bits; yellow: mixed decimal octet.')
    for label, segments in zip(('MASK', 'IP BINARY', 'IP DECIMAL'), method.find_network_and_hosts_visually()):
        print(f'{label}: {".".join(segments)}')
    print(method.find_network_and_hosts().strip())
    print(f'Network Address (Binary): {method.find_network_address()}')
    print(f'Network Address (Decimal): {method.find_network_address_decimal()}')
    print(f'Broadcast Address: {method.find_broadcast_address()}')
    first, last = method.find_usable_ip_range()
    print(f'Usable IP Range: {first} - {last}')
    if method.network.prefixlen >= 31:
        print('/31 uses point-to-point semantics; /32 represents one host.')
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
