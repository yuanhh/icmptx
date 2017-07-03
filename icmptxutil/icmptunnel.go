package icmptxutil

import (
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	MTU          = 1472
	protocolICMP = 1
)

type Icmptx struct {
	isSrv bool

	timeout time.Duration

	done chan bool

	ipaddr *net.IPAddr
	addr   string
	source string

	id  int
	seq int
}

type packet struct {
	bytes  []byte
	nbytes int
	peer   net.Addr
}

func NewIcmptx() *Icmptx {
	return &Icmptx{
		isSrv:   false,
		timeout: time.Second,
		done:    make(chan bool),
		ipaddr:  nil,
		addr:    "",
		source:  "0.0.0.0",
		id:      0,
		seq:     1,
	}
}

func (t *Icmptx) IsServer() bool {
	return t.isSrv
}

func (t *Icmptx) IPAddr() *net.IPAddr {
	return t.ipaddr
}

func (t *Icmptx) Addr() string {
	return t.addr
}

func (t *Icmptx) Source() string {
	return t.source
}

func (t *Icmptx) ID() int {
	return t.id
}

func (t *Icmptx) SetIPAddr(ipaddr *net.IPAddr) {
	t.ipaddr = ipaddr
	t.addr = ipaddr.String()
}

func (t *Icmptx) SetAddr(addr string) error {
	ipaddr, err := net.ResolveIPAddr("ip4:icmp", addr)
	if err != nil {
		return err
	}

	t.ipaddr = ipaddr
	t.addr = addr
	return nil
}

func (t *Icmptx) SetSource(localaddr string) {
	t.source = localaddr
}

func (t *Icmptx) SetID(id int) {
	t.id = id
}

func (t *Icmptx) SetMode(isSrv bool) {
	t.isSrv = isSrv
}

func (t *Icmptx) Run() {
	f, err := OpenTun()
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	c, err := icmp.ListenPacket("ip4:icmp", t.source)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	rawSock := make(chan *packet, 5)
	tunDev := make(chan string, 5)
	wg.Add(2)
	go t.recvICMP(c, rawSock, &wg)
	go t.recvTun(f, tunDev, &wg)

	timeout := time.NewTicker(100 * time.Millisecond)
	if t.isSrv {
		timeout.Stop()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	for {
		select {
		case <-sig:
			close(t.done)
		case <-t.done:
			wg.Wait()
			return
		case p := <-rawSock:
			err := t.processICMP(c, f, p)
			if err != nil {
				log.Fatal(err)
			}
		case s := <-tunDev:
			if t.isSrv {
				err = t.sendICMPMsg(c, ipv4.ICMPTypeEchoReply, []byte(s))
			} else {
				err = t.sendICMPMsg(c, ipv4.ICMPTypeEcho, []byte(s))
			}
			if err != nil {
				log.Fatal()
			}
			t.seq++
		case <-timeout.C:
			err = t.sendICMPMsg(c, ipv4.ICMPTypeEcho, []byte(""))
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}

// parseICMPEcho parses b as an ICMP echo request or reply message body.
func ParseICMPEcho(b []byte) (*icmp.Echo, error) {
	bodylen := len(b)
	p := &icmp.Echo{ID: int(b[0])<<8 | int(b[1]), Seq: int(b[2])<<8 | int(b[3])}
	if bodylen > 4 {
		p.Data = make([]byte, bodylen-4)
		copy(p.Data, b[4:])
	}
	return p, nil
}

func (t *Icmptx) recvICMP(
	c *icmp.PacketConn,
	recv chan<- *packet,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		select {
		case <-t.done:
			return
		default:
			rb := make([]byte, MTU)
			c.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
			n, peer, err := c.ReadFrom(rb)
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						continue
					} else {

						return
					}
				}
			}
			recv <- &packet{bytes: rb, nbytes: n, peer: peer}
		}
	}
}

func (t *Icmptx) recvTun(
	f *os.File,
	recv chan<- string,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	for {
		select {
		case <-t.done:
			return
		default:
			rs := make([]byte, 1472)
			_, err := f.Read(rs)
			if err != nil {
				if err != io.EOF {
					return
				} else {
					close(t.done)
					return
				}
			}
			recv <- string(rs)
		}
	}
}

func (t *Icmptx) sendICMPMsg(
	c *icmp.PacketConn,
	typ ipv4.ICMPType,
	bytes []byte,
) error {
	e := &icmp.Echo{
		ID:   t.id,
		Seq:  t.seq,
		Data: bytes,
	}
	for {
		err := sendICMPEcho(c, t.addr, typ, e)
		if err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
				return err
			}
		}
		break
	}
	return nil
}

func sendICMPEcho(
	c *icmp.PacketConn,
	addr string,
	typ ipv4.ICMPType,
	e *icmp.Echo,
) error {
	wm := icmp.Message{
		Type: typ,
		Code: 0,
		Body: e,
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}

	dst, err := net.ResolveIPAddr("ip4:icmp", addr)
	if _, err := c.WriteTo(wb, dst); err != nil {
		log.Fatal(err)
	}
	return err
}

func (t *Icmptx) processICMP(
	c *icmp.PacketConn,
	f *os.File,
	recv *packet,
) error {
	rb := recv.bytes
	rm, err := icmp.ParseMessage(protocolICMP, rb[:recv.nbytes])
	if err != nil {
		return err
	}
	mb, err := rm.Body.Marshal(protocolICMP)
	if err != nil {
		return err
	}
	e, _ := ParseICMPEcho(mb)

	switch rm.Type {
	case ipv4.ICMPTypeEchoReply, ipv4.ICMPTypeEcho:
		if t.id == 0 {
			t.id = e.ID
		}
		if e.ID == t.id {
			f.Write(e.Data)
		} else if rm.Type == ipv4.ICMPTypeEcho {
			sendICMPEcho(c, recv.peer.String(), ipv4.ICMPTypeEchoReply, e)
		} else {
			log.Printf("unknown icmp reply %+v\n", rm)
		}
	default:
		log.Printf("got icmp packet %+v\n", rm)
	}
	return nil
}
