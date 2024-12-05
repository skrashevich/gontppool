
# Go-based NTP Server with Multiple Downstream Servers

This program is a Go implementation an NTP server. It listens for incoming NTP requests on configured local addresses and updates its time reference state from multiple specified upstream (downstream from your perspective as a server) NTP servers.

## Features

- Serve NTP requests on IPv4 and IPv6 addresses.
- Periodically query multiple upstream NTP servers.
- Only forward time requests to servers that are confirmed to be available.
- Automatically drop privileges to a specified user and optionally chroot to a given directory.
- Debug logging for troubleshooting.

## Installation

1. Make sure you have Go installed (Go 1.13+ recommended).
2. Clone this repository or place the source files in a directory.
3. Run `go build` to compile the binary.

```bash
go build -o go-ntp
```

4. You will get an executable named `go-ntp`.

## Usage

```bash
./go-ntp [OPTIONS]
```

### Available Options

- `-4 NUM`  
  Set the number of IPv4 server threads. Default is `1`.
  
- `-6 NUM`  
  Set the number of IPv6 server threads. Default is `1`.
  
- `-a ADDR:PORT`  
  Set the local listening address for IPv4 sockets. Default is `0.0.0.0:123`.
  
- `-b ADDR:PORT`  
  Set the local listening address for IPv6 sockets. Default is `[::]:123`.
  
- `-s ADDR:PORT`  
  **Multiple upstream servers**: Specify an upstream NTP server address.  
  This option can be repeated multiple times to provide multiple servers.  
  Example:
  ```bash
  ./go-ntp -s 127.0.0.1:11123 -s ntp.example.org:123 -s 192.168.0.10:9999
  ```
  
  The server will periodically check each upstream server for availability and update its reference time state from any that respond correctly.
  
- `-u USER`  
  Run as `USER` after binding sockets, dropping privileges from root.
  
- `-r DIR`  
  Chroot into the specified `DIR` after binding sockets and before running.
  
- `-d`  
  Enable debug messages for verbose output. Useful for troubleshooting.
  
- `-h`  
  Print the help message and exit.
  
## Example Invocation

```bash
sudo ./go-ntp -a 0.0.0.0:123 -b [::]:123 -s 127.0.0.1:11123 -s time.google.com:123 -d
```

In this example, the server listens on all IPv4 and IPv6 addresses on port 123, queries `127.0.0.1:11123` and `time.google.com:123` as upstream servers, and prints debug messages to the console.

## Notes

- Ensure you run the server with sufficient privileges to bind to port 123 (or run as root and then use `-u` and `-r` to drop privileges).
- The server continuously checks upstream servers every few seconds and updates its internal state.
- If no upstream servers are specified, it defaults to `127.0.0.1:11123`.

## License

This program is distributed under the terms of the GNU General Public License (GPL) version 2 or later. See `LICENSE` for details.
