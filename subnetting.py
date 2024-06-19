import re
from abc import ABC, abstractmethod
from math import pow

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class IPSubnetting(ABC):
    def __init__(self, ip):
        self.ip = ip
    
    @abstractmethod
    def decimal_to_binary(self):
        pass
    
    @abstractmethod
    def mask_to_binary(self):
        pass
    
    @abstractmethod
    def find_network_and_hosts(self):
        pass
    
    @abstractmethod
    def find_network_and_hosts_visually(self):
        pass
    
    @abstractmethod
    def find_network_and_host_addresses(self):
        pass
    
    @abstractmethod
    def find_subnet(self):
        pass

class CIDR(IPSubnetting):
    def __init__(self, ip, cidr):
        super().__init__(ip)
        self.cidr = cidr
    
    def decimal_to_binary(self):
        return '.'.join(bin(int(octet)).lstrip('0b').zfill(8) for octet in self.ip.split('.'))
    
    def mask_to_binary(self):
        return '.'.join(bin(int(octet)).lstrip('0b').zfill(8) for octet in self.find_subnet().split('.'))
    
    def find_subnet(self):
        mask = "1" * int(self.cidr) + "0" * (32 - int(self.cidr))
        return '.'.join(str(int(mask[i:i+8], 2)) for i in range(0, 32, 8))

    def find_network_and_hosts(self):
        zeros = 32 - int(self.cidr)
        networks = pow(2, zeros)
        hosts = pow(2, zeros) - 2
        return f"Networks: {int(networks)}, Hosts: {int(hosts)}\n"

    def color_binary_string(self, binary_string, mask_string):
        colored_segments = []
        for binary_segment, mask_segment in zip(binary_string.split('.'), mask_string.split('.')):
            network_part = ''.join(Color.GREEN + bit + Color.RESET if mask_bit == '1' else Color.RED + bit + Color.RESET for bit, mask_bit in zip(binary_segment, mask_segment))
            colored_segments.append(network_part)
        return colored_segments

    def color_decimal_string(self, decimal_string, mask_string):
        colored_segments = []
        for dec_seg, mask_seg in zip(decimal_string.split('.'), mask_string.split('.')):
            network_length = format(int(mask_seg), '08b').count('1')
            if network_length == 8:
                colored_segment = Color.GREEN + dec_seg + Color.RESET
            else:
                network_part = dec_seg[:network_length]
                host_part = dec_seg[network_length:]
                colored_segment = Color.GREEN + network_part + Color.RESET + Color.RED + host_part + Color.RESET
            colored_segments.append(colored_segment)
        return colored_segments

    def find_network_and_hosts_visually(self):
        subnet_mask_decimal = self.find_subnet()
        subnet_mask_binary = self.mask_to_binary()
        ip_address_binary = self.decimal_to_binary()
        ip_address_decimal = self.ip
        
        colored_subnet_mask = self.color_binary_string(subnet_mask_binary, subnet_mask_binary)
        colored_ip_binary = self.color_binary_string(ip_address_binary, subnet_mask_binary)
        colored_ip_decimal = self.color_decimal_string(ip_address_decimal, subnet_mask_decimal)

        return colored_subnet_mask, colored_ip_binary, colored_ip_decimal

    def extract_network_and_host_parts(self, colored_segments):
        return [''.join(segment) for segment in zip(*colored_segments)]

    def find_network_and_host_addresses(self):
        _, colored_ip_binary, colored_ip_decimal = self.find_network_and_hosts_visually()

        network_binary, host_binary = self.extract_network_and_host_parts(colored_ip_binary)
        network_decimal, host_decimal = self.extract_network_and_host_parts(colored_ip_decimal)

        return network_binary, host_binary

    def find_network_address(self):
        ip_address_binary = self.decimal_to_binary().split('.')
        subnet_mask_binary = self.mask_to_binary().split('.')
        
        network_address_binary = []
        for ip_part, mask_part in zip(ip_address_binary, subnet_mask_binary):
            network_address_binary.append(''.join('0' if mask_bit == '0' else ip_bit for ip_bit, mask_bit in zip(ip_part, mask_part)))
        
        return '.'.join(network_address_binary)

    def find_network_address_decimal(self):
        network_address_binary = self.find_network_address().split('.')
        return '.'.join(str(int(binary_part, 2)) for binary_part in network_address_binary)
    
    def find_broadcast_address(self):
        network_address_decimal = self.find_network_address_decimal().split(".")
        subnet_mask_binary = self.mask_to_binary().split(".")
        broadcast_address = []
        
        for net_part, mask_part in zip(network_address_decimal, subnet_mask_binary):
            inverted_mask = ''.join('1' if bit == '0' else '0' for bit in mask_part)
            broadcast_octet = int(net_part) | int(inverted_mask, 2)
            broadcast_address.append(str(broadcast_octet))
        
        return '.'.join(broadcast_address)
    
    def find_usable_ip_range(self):
        network_address_decimal = self.find_network_address_decimal().split(".")
        broadcast_address_decimal = self.find_broadcast_address().split(".")
        
        first_usable_ip = network_address_decimal.copy()
        last_usable_ip = broadcast_address_decimal.copy()
        
        first_usable_ip[-1] = str(int(first_usable_ip[-1]) + 1)
        last_usable_ip[-1] = str(int(last_usable_ip[-1]) - 1)
        
        return '.'.join(first_usable_ip), '.'.join(last_usable_ip)

class SubnetMask(IPSubnetting):
    def __init__(self, ip, subnetmask):
        super().__init__(ip)
        self.subnetmask = subnetmask
    
    def decimal_to_binary(self):
        return '.'.join(bin(int(octet)).lstrip('0b').zfill(8) for octet in self.ip.split('.'))
    
    def mask_to_binary(self):
        return '.'.join(bin(int(octet)).lstrip('0b').zfill(8) for octet in self.subnetmask.split('.'))
    
    def find_subnet(self):
        return self.subnetmask

    def find_network_and_hosts(self):
        binary_mask = self.mask_to_binary()
        zeros = binary_mask.count("0")
        hosts = pow(2, zeros) - 2
        return f"Networks: 1, Hosts: {int(hosts)}\n"

    def find_network_and_hosts_visually(self):
        subnet_mask_decimal = self.find_subnet()
        subnet_mask_binary = self.mask_to_binary()
        ip_address_binary = self.decimal_to_binary()
        ip_address_decimal = self.ip
        
        colored_subnet_mask = self.color_binary_string(subnet_mask_binary, subnet_mask_binary)
        colored_ip_binary = self.color_binary_string(ip_address_binary, subnet_mask_binary)
        colored_ip_decimal = self.color_decimal_string(ip_address_decimal, subnet_mask_decimal)

        return colored_subnet_mask, colored_ip_binary, colored_ip_decimal

    def color_binary_string(self, binary_string, mask_string):
        colored_segments = []
        for binary_segment, mask_segment in zip(binary_string.split('.'), mask_string.split('.')):
            network_part = ''.join(Color.GREEN + bit + Color.RESET if mask_bit == '1' else Color.RED + bit + Color.RESET for bit, mask_bit in zip(binary_segment, mask_segment))
            colored_segments.append(network_part)
        return colored_segments

    def color_decimal_string(self, decimal_string, mask_string):
        colored_segments = []
        for dec_seg, mask_seg in zip(decimal_string.split('.'), mask_string.split('.')):
            network_length = format(int(mask_seg), '08b').count('1')
            if network_length == 8:
                colored_segment = Color.GREEN + dec_seg + Color.RESET
            else:
                network_part = dec_seg[:network_length]
                host_part = dec_seg[network_length:]
                colored_segment = Color.GREEN + network_part + Color.RESET + Color.RED + host_part + Color.RESET
            colored_segments.append(colored_segment)
        return colored_segments

    def extract_network_and_host_parts(self, colored_segments):
        return [''.join(segment) for segment in zip(*colored_segments)]

    def find_network_and_host_addresses(self):
        _, colored_ip_binary, colored_ip_decimal = self.find_network_and_hosts_visually()

        network_binary, host_binary = self.extract_network_and_host_parts(colored_ip_binary)
        network_decimal, host_decimal = self.extract_network_and_host_parts(colored_ip_decimal)

        return network_binary, host_binary

    def find_network_address(self):
        ip_address_binary = self.decimal_to_binary().split('.')
        subnet_mask_binary = self.mask_to_binary().split('.')
        
        network_address_binary = []
        for ip_part, mask_part in zip(ip_address_binary, subnet_mask_binary):
            network_address_binary.append(''.join('0' if mask_bit == '0' else ip_bit for ip_bit, mask_bit in zip(ip_part, mask_part)))
        
        return '.'.join(network_address_binary)

    def find_network_address_decimal(self):
        network_address_binary = self.find_network_address().split('.')
        return '.'.join(str(int(binary_part, 2)) for binary_part in network_address_binary)
    
    def find_broadcast_address(self):
        network_address_decimal = self.find_network_address_decimal().split(".")
        subnet_mask_binary = self.mask_to_binary().split(".")
        broadcast_address = []
        
        for net_part, mask_part in zip(network_address_decimal, subnet_mask_binary):
            inverted_mask = ''.join('1' if bit == '0' else '0' for bit in mask_part)
            broadcast_octet = int(net_part) | int(inverted_mask, 2)
            broadcast_address.append(str(broadcast_octet))
        
        return '.'.join(broadcast_address)
    
    def find_usable_ip_range(self):
        network_address_decimal = self.find_network_address_decimal().split(".")
        broadcast_address_decimal = self.find_broadcast_address().split(".")
        
        first_usable_ip = network_address_decimal.copy()
        last_usable_ip = broadcast_address_decimal.copy()
        
        first_usable_ip[-1] = str(int(first_usable_ip[-1]) + 1)
        last_usable_ip[-1] = str(int(last_usable_ip[-1]) - 1)
        
        return '.'.join(first_usable_ip), '.'.join(last_usable_ip)

class IPSubnettingFactory:
    @staticmethod
    def create_ip_subnetting(ip_input):
        if '/' in ip_input:
            ip, cidr = ip_input.split('/')
            if not (validate_ip(ip) and validate_cidr(cidr)):
                print(f"{Color.RED}[ERROR] Invalid IP address or CIDR.{Color.RESET}")
                return None
            return CIDR(ip, cidr)
        else:
            ip_parts = ip_input.split()
            if len(ip_parts) != 2 or not (validate_ip(ip_parts[0]) and validate_ip(ip_parts[1])):
                print(f"{Color.RED}[ERROR] Invalid IP address or Subnet Mask.{Color.RESET}")
                return None
            return SubnetMask(ip_parts[0], ip_parts[1])

def validate_ip(ip):
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip) and all(0 <= int(octet) <= 255 for octet in ip.split('.'))

def validate_cidr(cidr):
    return cidr.isdigit() and 0 <= int(cidr) <= 32

def main():
    ip_input = input(f"{Color.YELLOW}[?] Enter an IP address with CIDR (e.g. 10.0.2.15/24) or with Subnet Mask (e.g. 10.0.2.15 255.255.255.0): {Color.RESET}")
    method = IPSubnettingFactory.create_ip_subnetting(ip_input)
    if not method:
        return
    
    print(f"\n{Color.GREEN}[INFO]{Color.RESET} {method.ip}: {method.decimal_to_binary()}")
    print(f"{Color.GREEN}[INFO]{Color.RESET} {method.ip}/{method.cidr if isinstance(method, CIDR) else method.subnetmask}: {method.mask_to_binary()}")
    print(f"{Color.GREEN}[INFO]{Color.RESET} {method.ip}/{method.cidr if isinstance(method, CIDR) else method.subnetmask} subnet mask: {method.find_subnet()}\n")

    colored_subnet_mask, colored_ip_binary, colored_ip_decimal = method.find_network_and_hosts_visually()
    print(f"{Color.BLUE}[TITLE]{Color.RESET} {Color.GREEN}Network part{Color.RESET} - {Color.RED}Host part{Color.RESET}")
    print(f"[SUBNET MASK] {'.'.join(colored_subnet_mask)}")
    print(f"[IP ADDRESS (BIN)] {'.'.join(colored_ip_binary)}")
    print(f"[IP ADDRESS] {'.'.join(colored_ip_decimal)}\n")
    
    print(f"{Color.GREEN}[INFO]{Color.RESET} {method.ip}: {method.find_network_and_hosts()}")
    
    print(f"{Color.GREEN}[INFO]{Color.RESET} Network Address (Binary): {method.find_network_address()}")
    print(f"{Color.GREEN}[INFO]{Color.RESET} Network Address (Decimal): {method.find_network_address_decimal()}")
    print(f"{Color.GREEN}[INFO]{Color.RESET} Broadcast Address: {method.find_broadcast_address()}")
    
    first_usable_ip, last_usable_ip = method.find_usable_ip_range()
    print(f"{Color.GREEN}[INFO]{Color.RESET} Usable IP Range: {first_usable_ip} - {last_usable_ip}")

if __name__ == "__main__":
    main()
