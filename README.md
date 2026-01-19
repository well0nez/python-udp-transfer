# UDP File Transfer (Python)

Python-based UDP file transfer with NAT traversal (hole punching) and a rendezvous server.

## Features

- UDP hole punching for direct peer-to-peer transfer
- Sliding window with acknowledgements
- SHA256 verification
- Windows and Linux clients

## Requirements

- Python 3.8+

## Usage

### 1) Start the Rendezvous Server

```bash
python3 server.py --port 9999
```

### 2) Receiver (requests a code)

```bash
python3 client.py -s SERVER_IP:9999 -m receive
```

The receiver will print a 6-character code.

### 3) Sender (joins with code)

```bash
python3 client.py -s SERVER_IP:9999 -m send -f myfile.mp4 -c CODE123
```

### Windows

```bash
python client_win.py -s SERVER_IP:9999 -m receive
python client_win.py -s SERVER_IP:9999 -m send -f myfile.mp4 -c CODE123
```

## CLI Options

```
Options:
  -s, --server <HOST:PORT>    Server address (required)
  -m, --mode <MODE>           Mode: send or receive (required)
  -f, --file <FILE>           File to send (sender mode)
  -c, --code <CODE>           Transfer code (sender mode)
  -d, --debug                 Enable debug logging
```

## Compatibility

- Compatible with the Rust client in `udp-transfer-ice` (same protocol)

## License

MIT
