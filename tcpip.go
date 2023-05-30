package main

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// quick fix for https://github.com/golang/go/issues/37239

// code from https://github.com/golang/crypto/blob/a4e984136a63c90def42a9336ac6507c2f6a896d/ssh/tcpip.go
const openSSHPrefix = "OpenSSH_"

// Automatic port allocation is broken with OpenSSH before 6.0. See
// also https://bugzilla.mindrot.org/show_bug.cgi?id=2017.  In
// particular, OpenSSH 5.9 sends a channelOpenMsg with port number 0,
// rather than the actual port number. This means you can never open
// two different listeners with auto allocated ports. We work around
// this by trying explicit ports until we succeed.
var portRandomizer = rand.New(rand.NewSource(time.Now().UnixNano()))

// isBrokenOpenSSHVersion returns true if the given version string
// specifies a version of OpenSSH that is known to have a bug in port
// forwarding.
func isBrokenOpenSSHVersion(versionStr string) bool {
	i := strings.Index(versionStr, openSSHPrefix)
	if i < 0 {
		return false
	}
	i += len(openSSHPrefix)
	j := i
	for ; j < len(versionStr); j++ {
		if versionStr[j] < '0' || versionStr[j] > '9' {
			break
		}
	}
	version, _ := strconv.Atoi(versionStr[i:j])
	return version < 6
}

// forward represents an incoming forwarded tcpip connection. The
// arguments to add/remove/lookup should be address as specified in
// the original forward-request.
type forward struct {
	newCh ssh.NewChannel // the ssh client channel underlying this forward
	raddr net.Addr       // the raddr of the incoming connection
}

// RFC 4254 7.1
type channelForwardMsg struct {
	addr  string
	rport uint32
}

// chanConn fulfills the net.Conn interface without
// the tcpChan having to hold laddr or raddr directly.
type chanConn struct {
	ssh.Channel
	laddr, raddr net.Addr
}

// LocalAddr returns the local network address.
func (t *chanConn) LocalAddr() net.Addr {
	return t.laddr
}

// RemoteAddr returns the remote network address.
func (t *chanConn) RemoteAddr() net.Addr {
	return t.raddr
}

// SetDeadline sets the read and write deadlines associated
// with the connection.
func (t *chanConn) SetDeadline(deadline time.Time) error {
	if err := t.SetReadDeadline(deadline); err != nil {
		return err
	}
	return t.SetWriteDeadline(deadline)
}

// SetReadDeadline sets the read deadline.
// A zero value for t means Read will not time out.
// After the deadline, the error from Read will implement net.Error
// with Timeout() == true.
func (t *chanConn) SetReadDeadline(deadline time.Time) error {
	// for compatibility with previous version,
	// the error message contains "tcpChan"
	return errors.New("ssh: tcpChan: deadline not supported")
}

// SetWriteDeadline exists to satisfy the net.Conn interface
// but is not implemented by this type.  It always returns an error.
func (t *chanConn) SetWriteDeadline(deadline time.Time) error {
	return errors.New("ssh: tcpChan: deadline not supported")
}

// See RFC 4254, section 7.2
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// ====== Customization Begin ======

type ClientAlt struct {
	*ssh.Client
	handleOnce sync.Once
	forwards   forwardListAlt
}

func WrapClient(conn *ssh.Client) *ClientAlt {
	ex := ClientAlt{
		Client: conn,
		forwards: forwardListAlt{
			forwards: make(map[string]chan forward),
		},
	}

	go func() {
		_ = ex.Wait()
		ex.forwards.closeAll()
	}()

	return &ex
}

func (c *ClientAlt) ListenAlt(host string, port uint32) (net.Listener, error) {
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port")
	}
	if port == 0 && isBrokenOpenSSHVersion(string(c.ServerVersion())) {
		for tries := 0; tries < 10; tries++ {
			port = uint32(portRandomizer.Intn(60000) + 1024)
			if listener, err := c.ListenAlt(host, port); err == nil {
				return listener, nil
			}
		}
		return nil, errors.New("ssh: unable to allocate random port")
	}
	return c.listenAlt(host, port)
}

func (c *ClientAlt) listenAlt(host string, port uint32) (net.Listener, error) {
	c.handleOnce.Do(c.handleChannels)

	m := channelForwardMsg{
		addr:  host,
		rport: port,
	}

	ok, resp, err := c.SendRequest("tcpip-forward", true, ssh.Marshal(m))

	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, errors.New("ssh: tcpip-forward request denied by peer")
	}

	if port == 0 {
		var p struct {
			Port uint32
		}
		if err := ssh.Unmarshal(resp, &p); err != nil {
			return nil, err
		}
		port = p.Port
	}

	binding := net.JoinHostPort(host, strconv.Itoa(int(port)))

	if c.forwards.has(binding) {
		return nil, errors.New("ssh: forwarding already exists")
	}

	ip := net.ParseIP(host)

	// non-ip host is acceptable as in RFC 4254 7.1
	// but the ip will not available since it is resolved on the server side
	if ip == nil {
		ip = net.IPv4zero
	}

	ch := c.forwards.add(binding)

	return &tcpListenerAlt{
		binding: binding,
		conn:    c,
		in:      ch,
		laddr: &net.TCPAddr{
			IP:   ip,
			Port: int(port),
		},
	}, nil
}

func (c *ClientAlt) handleChannels() {
	go c.forwards.handleChannels(c.HandleChannelOpen("forwarded-tcpip"))
}

type forwardListAlt struct {
	forwards map[string]chan forward
	lock     sync.Mutex
}

func (l *forwardListAlt) handleChannels(in <-chan ssh.NewChannel) {
	for ch := range in {
		var (
			binding string
			raddr   net.Addr
			err     error
		)
		switch channelType := ch.ChannelType(); channelType {
		case "forwarded-tcpip":
			var payload forwardedTCPPayload
			if err = ssh.Unmarshal(ch.ExtraData(), &payload); err != nil {
				_ = ch.Reject(ssh.ConnectionFailed, "could not parse forwarded-tcpip payload: "+err.Error())
				continue
			}

			binding = net.JoinHostPort(payload.Addr, strconv.Itoa(int(payload.Port)))
		default:
			panic(fmt.Errorf("ssh: unknown channel type %s", channelType))
		}
		if ok := l.forward(binding, raddr, ch); !ok {
			// Section 7.2, implementations MUST reject spurious incoming
			// connections.
			_ = ch.Reject(ssh.Prohibited, "no forward for address")
			continue
		}
	}
}

func (l *forwardListAlt) add(binding string) chan forward {
	l.lock.Lock()
	defer l.lock.Unlock()

	ch := make(chan forward, 1)
	l.forwards[binding] = ch

	return ch
}

func (l *forwardListAlt) has(binding string) bool {
	l.lock.Lock()
	defer l.lock.Unlock()

	_, ok := l.forwards[binding]
	return ok
}

func (l *forwardListAlt) remove(binding string) {
	l.lock.Lock()
	defer l.lock.Unlock()

	ch := l.forwards[binding]
	close(ch)

	delete(l.forwards, binding)
}

func (l *forwardListAlt) closeAll() {
	l.lock.Lock()
	defer l.lock.Unlock()

	for _, ch := range l.forwards {
		close(ch)
	}
	l.forwards = nil
}

func (l *forwardListAlt) forward(binding string, raddr net.Addr, channel ssh.NewChannel) bool {
	l.lock.Lock()
	defer l.lock.Unlock()

	ch, ok := l.forwards[binding]

	if !ok {
		return false
	}

	ch <- forward{channel, raddr}
	return true
}

type tcpListenerAlt struct {
	binding string
	laddr   *net.TCPAddr

	conn *ClientAlt
	in   <-chan forward
}

// Accept waits for and returns the next connection to the listener.
func (l *tcpListenerAlt) Accept() (net.Conn, error) {
	s, ok := <-l.in
	if !ok {
		return nil, io.EOF
	}
	ch, incoming, err := s.newCh.Accept()
	if err != nil {
		return nil, err
	}
	go ssh.DiscardRequests(incoming)

	return &chanConn{
		Channel: ch,
		laddr:   l.laddr,
		raddr:   s.raddr,
	}, nil
}

// Close closes the listener.
func (l *tcpListenerAlt) Close() error {
	m := channelForwardMsg{
		l.binding,
		uint32(l.laddr.Port),
	}

	// this also closes the listener.
	l.conn.forwards.remove(l.binding)
	ok, _, err := l.conn.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(&m))
	if err == nil && !ok {
		err = errors.New("ssh: cancel-tcpip-forward failed")
	}
	return err
}

// Addr returns the listener's network address.
func (l *tcpListenerAlt) Addr() net.Addr {
	return l.laddr
}
