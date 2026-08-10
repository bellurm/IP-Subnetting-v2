# IP-Subnetting-v2

A Python-based IPv4 subnetting utility for calculating and visualizing network information from CIDR notation or a subnet mask.

The project was built to make IPv4 subnetting easier to understand by showing both the calculated addresses and their binary representation, including a visual distinction between network and host portions.

---

## Features

IP-Subnetting-v2 can calculate and display:

- IPv4 address in binary
- Subnet mask in decimal
- Subnet mask in binary
- Network address
- Network address in binary
- Broadcast address
- Usable host range
- Host capacity
- Network and host portions of an IPv4 address

The utility accepts both:

```text
192.168.1.10/24
```

and:

```text
192.168.1.10 255.255.255.0
```

---

## Example

Run the program:

```bash
python3 subnetting.py
```

The application asks for an IPv4 address using either CIDR notation:

```text
10.0.2.15/24
```

or an explicit subnet mask:

```text
10.0.2.15 255.255.255.0
```

For a `/24` network, the calculated information includes values such as:

```text
IP Address:        10.0.2.15
Subnet Mask:       255.255.255.0
Network Address:   10.0.2.0
Broadcast Address: 10.0.2.255
Usable IP Range:   10.0.2.1 - 10.0.2.254
```

The program also displays the binary representation of the address and subnet mask.

---

## Binary Representation

IPv4 subnetting is fundamentally based on bits.

For example:

```text
IP Address:
10.0.2.15

Binary:
00001010.00000000.00000010.00001111
```

A `/24` subnet mask becomes:

```text
11111111.11111111.11111111.00000000
```

This makes it possible to see which bits belong to the network portion and which belong to the host portion.

---

## Network and Host Visualization

The terminal output uses ANSI colors to visually separate:

- Network bits
- Host bits

Conceptually:

```text
11111111.11111111.11111111.00000000
└──────── Network ─────────┘└─ Host ─┘
```

This makes the project useful not only as a calculator, but also as a learning tool for understanding how subnet masks divide an IPv4 address.

---

## Calculations

### Subnet Mask from CIDR

CIDR notation defines how many of the 32 IPv4 bits belong to the network portion.

For example:

```text
/24
```

corresponds to:

```text
11111111.11111111.11111111.00000000
```

which is:

```text
255.255.255.0
```

The program performs this conversion automatically.

---

### Network Address

The network address is calculated by applying the subnet mask to the IPv4 address.

Conceptually:

```text
IP Address
AND
Subnet Mask
=
Network Address
```

Example:

```text
192.168.1.42
255.255.255.0
----------------
192.168.1.0
```

---

### Broadcast Address

The broadcast address is calculated from the network address and the host portion of the subnet.

Example:

```text
Network:   192.168.1.0
Mask:      255.255.255.0
Broadcast: 192.168.1.255
```

---

### Usable Host Range

For traditional IPv4 subnets, the first address represents the network and the last address represents the broadcast address.

For example:

```text
Network:        192.168.1.0
First Host:     192.168.1.1
Last Host:      192.168.1.254
Broadcast:      192.168.1.255
```

---

## Project Structure

```text
IP-Subnetting-v2/
├── subnetting.py
└── subnetting.txt
```

The main implementation is contained in:

```text
subnetting.py
```

---

## Code Design

The project uses an object-oriented structure to separate the different input formats.

### `IPSubnetting`

An abstract base class defining the common subnetting interface.

It includes abstract operations for tasks such as:

- Decimal-to-binary conversion
- Subnet mask conversion
- Network/host calculations
- Network/host visualization

### `CIDR`

Handles addresses supplied using CIDR notation.

Example:

```text
192.168.1.10/24
```

It converts the CIDR prefix into a subnet mask and performs the required IPv4 calculations.

### `SubnetMask`

Handles addresses supplied with an explicit subnet mask.

Example:

```text
192.168.1.10 255.255.255.0
```

### `IPSubnettingFactory`

Determines which implementation should be used based on the supplied input format.

Conceptually:

```text
User Input
    │
    ├── Contains "/" ──────► CIDR
    │
    └── IP + Mask ─────────► SubnetMask
```

---

## Input Validation

The application validates IPv4 addresses by checking:

- Four IPv4 octets are present
- Each octet is numeric
- Each octet is between `0` and `255`

CIDR values are checked to ensure they are between:

```text
/0
```

and:

```text
/32
```

---

## Requirements

- Python 3
- A terminal with ANSI color support

The project only uses Python standard-library modules and does not require third-party packages.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/bellurm/IP-Subnetting-v2.git
cd IP-Subnetting-v2
```

Run the program:

```bash
python3 subnetting.py
```

---

## What This Project Demonstrates

This project demonstrates practical understanding of:

- IPv4 addressing
- CIDR notation
- Subnet masks
- Binary and decimal conversion
- Network addresses
- Broadcast addresses
- Host ranges
- Network and host bits
- Python
- Object-oriented programming
- Abstract base classes
- Factory-style object creation
- Input validation
- Terminal output formatting

---

## Why This Project?

Subnetting calculators can provide an answer immediately, but they often hide the binary operations that produce that answer.

IP-Subnetting-v2 was created to expose those intermediate steps and make subnetting easier to understand visually.

The goal is not only to calculate:

```text
192.168.1.10/24
```

but also to understand why the resulting network is:

```text
192.168.1.0/24
```

and how the network and host portions are represented at the bit level.

---

## Limitations

This is an educational IPv4 subnetting utility rather than a complete network engineering library.

The current implementation uses the traditional IPv4 usable-host calculation:

```text
2^host_bits - 2
```

As a result, `/31` and `/32` networks are not handled using their special modern networking semantics.

Explicit subnet masks are validated as IPv4-formatted values, but the current implementation does not perform full validation that the mask contains only contiguous network bits.

IPv6 is not currently supported.

---

## Use Cases

The project can be useful for:

- Learning IPv4 subnetting
- Networking fundamentals
- Cybersecurity fundamentals
- Network administration practice
- CIDR exercises
- Visualizing network and host bits
- Understanding binary IPv4 representation

---

## Author

**Cyber Worm**

GitHub: [@bellurm](https://github.com/bellurm)
