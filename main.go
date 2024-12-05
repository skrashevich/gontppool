package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type NtpTimestamp struct {
	ts uint64
}

func ntpNow() NtpTimestamp {
	now := time.Now().UTC()
	secs := uint64(now.Unix() + 2208988800)
	nanos := now.Nanosecond()
	frac := uint64(float64(nanos) * 4.294967296)
	return NtpTimestamp{ts: (secs << 32) + frac}
}

func ntpZero() NtpTimestamp {
	return NtpTimestamp{ts: 0}
}

func ntpRandom() NtpTimestamp {
	return NtpTimestamp{ts: rand.Uint64()}
}

func (t NtpTimestamp) diffToSec(u NtpTimestamp) float64 {
	diff := int64(t.ts - u.ts)
	return float64(diff) / 4294967296.0
}

func readNtpTimestamp(buf []byte) NtpTimestamp {
	return NtpTimestamp{ts: binary.BigEndian.Uint64(buf)}
}

func (t NtpTimestamp) write(buf []byte) {
	binary.BigEndian.PutUint64(buf, t.ts)
}

func (t NtpTimestamp) equals(other NtpTimestamp) bool {
	return t.ts == other.ts
}

type NtpFracValue struct {
	val uint32
}

func ntpFracRead(buf []byte) NtpFracValue {
	return NtpFracValue{val: binary.BigEndian.Uint32(buf)}
}

func (f NtpFracValue) write(buf []byte) {
	binary.BigEndian.PutUint32(buf, f.val)
}

func ntpFracZero() NtpFracValue {
	return NtpFracValue{val: 0}
}

func (f *NtpFracValue) increment() {
	f.val += 1
}

type NtpPacket struct {
	remoteAddr net.Addr
	localTS    NtpTimestamp

	leap       uint8
	version    uint8
	mode       uint8
	stratum    uint8
	poll       int8
	precision  int8
	delay      NtpFracValue
	dispersion NtpFracValue
	refID      uint32
	refTS      NtpTimestamp
	origTS     NtpTimestamp
	rxTS       NtpTimestamp
	txTS       NtpTimestamp
}

func receiveNtpPacket(conn *net.UDPConn) (*NtpPacket, error) {
	buf := make([]byte, 1024)
	n, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	localTS := ntpNow()

	if n < 48 {
		return nil, fmt.Errorf("packet too short")
	}

	leap := buf[0] >> 6
	version := (buf[0] >> 3) & 0x7
	mode := buf[0] & 0x7

	if version < 1 || version > 4 {
		return nil, fmt.Errorf("unsupported version")
	}

	p := &NtpPacket{
		remoteAddr: addr,
		localTS:    localTS,
		leap:       leap,
		version:    version,
		mode:       mode,
		stratum:    buf[1],
		poll:       int8(buf[2]),
		precision:  int8(buf[3]),
		delay:      ntpFracRead(buf[4:8]),
		dispersion: ntpFracRead(buf[8:12]),
		refID:      binary.BigEndian.Uint32(buf[12:16]),
		refTS:      readNtpTimestamp(buf[16:24]),
		origTS:     readNtpTimestamp(buf[24:32]),
		rxTS:       readNtpTimestamp(buf[32:40]),
		txTS:       readNtpTimestamp(buf[40:48]),
	}

	return p, nil
}

func (p *NtpPacket) send(conn *net.UDPConn) error {
	buf := make([]byte, 48)
	buf[0] = (p.leap << 6) | (p.version << 3) | p.mode
	buf[1] = p.stratum
	buf[2] = byte(p.poll)
	buf[3] = byte(p.precision)
	p.delay.write(buf[4:8])
	p.dispersion.write(buf[8:12])
	binary.BigEndian.PutUint32(buf[12:16], p.refID)
	p.refTS.write(buf[16:24])
	p.origTS.write(buf[24:32])
	p.rxTS.write(buf[32:40])
	p.txTS.write(buf[40:48])

	udpAddr, ok := p.remoteAddr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("remoteAddr is not UDPAddr")
	}
	_, err := conn.WriteToUDP(buf, udpAddr)
	return err
}

func (p *NtpPacket) isRequest() bool {
	return p.mode == 1 || p.mode == 3 ||
		(p.mode == 0 && p.version == 1 && p.remoteAddr.(*net.UDPAddr).Port != 123)
}

type NtpServerState struct {
	leap       uint8
	stratum    uint8
	precision  int8
	refID      uint32
	refTS      NtpTimestamp
	dispersion NtpFracValue
	delay      NtpFracValue
}

func (p *NtpPacket) makeResponse(state *NtpServerState) *NtpPacket {
	if !p.isRequest() {
		return nil
	}

	var mode uint8
	if p.mode == 1 {
		mode = 2
	} else {
		mode = 4
	}

	return &NtpPacket{
		remoteAddr: p.remoteAddr,
		localTS:    ntpZero(),
		leap:       state.leap,
		version:    p.version,
		mode:       mode,
		stratum:    state.stratum,
		poll:       p.poll,
		precision:  state.precision,
		delay:      state.delay,
		dispersion: state.dispersion,
		refID:      state.refID,
		refTS:      state.refTS,
		origTS:     p.txTS,
		rxTS:       p.localTS,
		txTS:       ntpNow(),
	}
}

func newRequest(remoteAddr *net.UDPAddr) *NtpPacket {
	return &NtpPacket{
		remoteAddr: remoteAddr,
		localTS:    ntpNow(),
		leap:       0,
		version:    4,
		mode:       3,
		stratum:    0,
		poll:       0,
		precision:  0,
		delay:      ntpFracZero(),
		dispersion: ntpFracZero(),
		refID:      0,
		refTS:      ntpZero(),
		origTS:     ntpZero(),
		rxTS:       ntpZero(),
		txTS:       ntpRandom(),
	}
}

func (p *NtpPacket) isValidResponse(request *NtpPacket) bool {
	if p.remoteAddr.String() != request.remoteAddr.String() {
		return false
	}
	if p.mode != request.mode+1 {
		return false
	}
	if !p.origTS.equals(request.txTS) {
		return false
	}
	return true
}

func (p *NtpPacket) getServerState() NtpServerState {
	return NtpServerState{
		leap:       p.leap,
		stratum:    p.stratum,
		precision:  p.precision,
		refID:      p.refID,
		refTS:      p.refTS,
		dispersion: p.dispersion,
		delay:      p.delay,
	}
}

type downstreamServer struct {
	addr      *net.UDPAddr
	available bool
}

type NtpServer struct {
	state       *sync.Mutex
	sharedState *NtpServerState
	conns       []*net.UDPConn
	downstreams []*downstreamServer
	debug       bool
}

func newNtpServer(localAddrs []string, downstreamAddrs []string, debug bool) *NtpServer {
	s := &NtpServerState{
		leap:       0,
		stratum:    0,
		precision:  0,
		refID:      0,
		refTS:      ntpZero(),
		dispersion: ntpFracZero(),
		delay:      ntpFracZero(),
	}

	var conns []*net.UDPConn
	for _, a := range localAddrs {
		lc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				var serr error
				err := c.Control(func(fd uintptr) {
					serr = SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				})
				if err != nil {
					return err
				}
				return serr
			},
		}

		conn, err := lc.ListenPacket(nil, "udp", a)
		if err != nil {
			panic(fmt.Sprintf("Couldn't bind socket: %v", err))
		}

		udpConn, ok := conn.(*net.UDPConn)
		if !ok {
			panic("Failed to cast to UDPConn")
		}
		conns = append(conns, udpConn)
	}

	var downstreams []*downstreamServer
	for _, ds := range downstreamAddrs {
		addr, err := net.ResolveUDPAddr("udp", ds)
		if err != nil {
			fmt.Printf("Warning: invalid downstream server address %s: %v\n", ds, err)
			continue
		}
		downstreams = append(downstreams, &downstreamServer{
			addr:      addr,
			available: false,
		})
	}

	return &NtpServer{
		state:       &sync.Mutex{},
		sharedState: s,
		conns:       conns,
		downstreams: downstreams,
		debug:       debug,
	}
}

func (server *NtpServer) processRequests(threadID uint32, conn *net.UDPConn) {
	lastUpdate := ntpNow()
	cachedState := *server.sharedState

	fmt.Printf("Server thread #%d started\n", threadID)

	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Thread #%d failed to receive packet: %v\n", threadID, err)
			continue
		}

		localTS := ntpNow()
		if n < 48 {
			if server.debug {
				fmt.Printf("Thread #%d: packet too short\n", threadID)
			}
			continue
		}

		packet, err := parseNtpPacket(buf[:n], addr, localTS)
		if err != nil {
			if server.debug {
				fmt.Printf("Thread #%d: parse error: %v\n", threadID, err)
			}
			continue
		}

		if server.debug {
			fmt.Printf("Thread #%d received %+v\n", threadID, packet)
		}

		if absF(packet.localTS.diffToSec(lastUpdate)) > 0.1 {
			server.state.Lock()
			cachedState = *server.sharedState
			server.state.Unlock()
			lastUpdate = packet.localTS
			if server.debug {
				fmt.Printf("Thread #%d updated its state\n", threadID)
			}
		}

		resp := packet.makeResponse(&cachedState)
		if resp != nil {
			if err := resp.send(conn); err != nil {
				fmt.Printf("Thread #%d failed to send packet to %s: %v\n", threadID, resp.remoteAddr, err)
			} else if server.debug {
				fmt.Printf("Thread #%d sent %+v\n", threadID, resp)
			}
		}
	}
}

func parseNtpPacket(buf []byte, addr *net.UDPAddr, localTS NtpTimestamp) (*NtpPacket, error) {
	leap := buf[0] >> 6
	version := (buf[0] >> 3) & 0x7
	mode := buf[0] & 0x7
	if version < 1 || version > 4 {
		return nil, fmt.Errorf("unsupported version")
	}

	p := &NtpPacket{
		remoteAddr: addr,
		localTS:    localTS,
		leap:       leap,
		version:    version,
		mode:       mode,
		stratum:    buf[1],
		poll:       int8(buf[2]),
		precision:  int8(buf[3]),
		delay:      ntpFracRead(buf[4:8]),
		dispersion: ntpFracRead(buf[8:12]),
		refID:      binary.BigEndian.Uint32(buf[12:16]),
		refTS:      readNtpTimestamp(buf[16:24]),
		origTS:     readNtpTimestamp(buf[24:32]),
		rxTS:       readNtpTimestamp(buf[32:40]),
		txTS:       readNtpTimestamp(buf[40:48]),
	}
	return p, nil
}

// updateDownstreams – periodically check downstream-servers availability
func (server *NtpServer) updateDownstreams() {
	for {
		// check every server
		for _, ds := range server.downstreams {
			ds.available = server.checkServer(ds.addr)
			if server.debug {
				fmt.Printf("Check server %s: available=%v\n", ds.addr.String(), ds.available)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

// checkServer – send query to downstream-server and check answer
func (server *NtpServer) checkServer(addr *net.UDPAddr) bool {
	request := newRequest(addr)

	laddr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		if server.debug {
			fmt.Printf("CheckServer: failed to listen UDP: %v\n", err)
		}
		return false
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(1 * time.Second))

	if err := request.send(conn); err != nil {
		if server.debug {
			fmt.Printf("CheckServer: failed to send packet: %v\n", err)
		}
		return false
	}

	buf := make([]byte, 1024)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			// no answer
			return false
		}
		if n < 48 {
			// too short
			continue
		}

		localTS := ntpNow()
		resp, err := parseNtpPacket(buf[:n], raddr, localTS)
		if err != nil {
			continue
		}
		if resp.isValidResponse(request) {
			return true
		}
	}
}

func (server *NtpServer) updateState() {
	// Now we need to get the state not from a single server, but from available downstream servers.
	// We can take the first available state or combine them. For simplicity, we'll take the first available one.
	var newState *NtpServerState

	for _, ds := range server.downstreams {
		if ds.available {
			request := newRequest(ds.addr)
			laddr := &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			}
			conn, err := net.ListenUDP("udp", laddr)
			if err != nil {
				if server.debug {
					fmt.Printf("Client failed to listen UDP: %v\n", err)
				}
				continue
			}
			conn.SetDeadline(time.Now().Add(1 * time.Second))

			if err := request.send(conn); err != nil {
				conn.Close()
				continue
			}

			if server.debug {
				fmt.Printf("Client sent request to %s: %+v\n", ds.addr.String(), request)
			}

			buf := make([]byte, 1024)
		readLoop:
			for {
				n, raddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					break readLoop
				}
				if n < 48 {
					continue
				}
				localTS := ntpNow()
				resp, err := parseNtpPacket(buf[:n], raddr, localTS)
				if err != nil {
					continue
				}
				if server.debug {
					fmt.Printf("Client received from %s: %+v\n", ds.addr.String(), resp)
				}
				if resp.isValidResponse(request) {
					s := resp.getServerState()
					newState = &s
					break readLoop
				}
			}
			conn.Close()

			if newState != nil {
				break
			}
		}
		if newState != nil {
			break
		}
	}

	server.state.Lock()
	defer server.state.Unlock()
	if newState != nil {
		*server.sharedState = *newState
	}
	server.sharedState.dispersion.increment()
}

func (server *NtpServer) run() {
	var wg sync.WaitGroup
	var threadID uint32 = 0

	// run pool
	for _, conn := range server.conns {
		threadID++
		c := conn
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			server.processRequests(id, c)
		}(threadID)
	}

	go server.updateDownstreams()

	for {
		server.updateState()
		time.Sleep(time.Second)
	}
}

func printUsage() {
	fmt.Println("Usage: gontppool [OPTIONS]")
	fmt.Println("Options:")
	fmt.Println("  -4 NUM        set number of IPv4 server threads (default 1)")
	fmt.Println("  -6 NUM        set number of IPv6 server threads (default 1)")
	fmt.Println("  -a ADDR:PORT  set local address of IPv4 server sockets (default 0.0.0.0:123)")
	fmt.Println("  -b ADDR:PORT  set local address of IPv6 server sockets (default [::]:123)")
	fmt.Println("  -s ADDR:PORT  set one or more upstream NTP server addresses. Can be repeated multiple times.")
	fmt.Println("                Example: -s 127.0.0.1:11123 -s 192.168.0.10:12345")
	fmt.Println("  -u USER       run as specified USER after binding sockets")
	fmt.Println("  -r DIR        change root directory to DIR (chroot)")
	fmt.Println("  -d            enable debug messages")
	fmt.Println("  -h            print this help message")
	fmt.Println("")
	fmt.Println("This NTP server listens on the specified local addresses and ports, serves NTP requests,")
	fmt.Println("and periodically queries upstream NTP servers to update its reference time state.")
	fmt.Println("Multiple upstream servers can be specified with multiple -s flags; the server will only")
	fmt.Println("use those that respond successfully.")
}
func absF(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}

func dropPrivileges(userName, chrootDir string) error {
	if chrootDir != "" && chrootDir != "/" {
		if err := Chroot(chrootDir); err != nil {
			return fmt.Errorf("failed to chroot: %v", err)
		}
		if err := os.Chdir("/"); err != nil {
			return fmt.Errorf("failed to chdir to root: %v", err)
		}
	}
	if userName != "" && userName != "root" {
		u, err := user.Lookup(userName)
		if err != nil {
			return fmt.Errorf("failed to lookup user: %v", err)
		}
		uid, _ := strconv.Atoi(u.Uid)
		gid, _ := strconv.Atoi(u.Gid)
		if err := Setgid(gid); err != nil {
			return fmt.Errorf("failed to setgid: %v", err)
		}
		if err := Setuid(uid); err != nil {
			return fmt.Errorf("failed to setuid: %v", err)
		}
	}

	return nil
}

func main() {
	var (
		ipv4Threads = flag.Int("4", 1, "number of IPv4 server threads")
		ipv6Threads = flag.Int("6", 1, "number of IPv6 server threads")
		ipv4Addr    = flag.String("a", "0.0.0.0:123", "IPv4 server address")
		ipv6Addr    = flag.String("b", "[::]:123", "IPv6 server address")
		// Вместо одного сервера теперь можно указать несколько с помощью повторения флага -s
		servers   multiStringFlag
		userName  = flag.String("u", "", "run as USER")
		rootDir   = flag.String("r", "", "chroot directory")
		debugFlag = flag.Bool("d", false, "enable debug messages")
		helpFlag  = flag.Bool("h", false, "print help")
	)

	flag.Var(&servers, "s", "upstream server address (can be repeated)")
	flag.Parse()

	if *helpFlag {
		printUsage()
		return
	}

	if len(servers) == 0 {
		// Если не указано ни одного сервера, используем по умолчанию
		servers = append(servers, "127.0.0.1:11123")
	}

	var addrs []string
	for i := 0; i < *ipv4Threads; i++ {
		addrs = append(addrs, *ipv4Addr)
	}
	for i := 0; i < *ipv6Threads; i++ {
		addrs = append(addrs, *ipv6Addr)
	}

	server := newNtpServer(addrs, servers, *debugFlag)

	if (*rootDir != "") || (*userName != "") {
		if err := dropPrivileges(*userName, *rootDir); err != nil {
			panic(fmt.Sprintf("Couldn't drop privileges: %v", err))
		}
	}

	server.run()
}

// multiStringFlag для возможности указания флага -s несколько раз
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}
