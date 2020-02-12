package main

import (
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

func main() {

	p := socket()
	defer p.Close()

	for {
		b := make([]byte, 510) //Maximum size os RIP pdu - 504byte
		s, cm, _, err := p.ReadFrom(b)
		if err != nil {
			log.Fatal(err)
		} else if s != 0 {
			go func() {
				r, err := read(b[:s], cm.IfIndex, cm.Src)
				if err != nil {
					log.Fatal(err)
				}
				r.parser()
				err = r.validator("")
				if err != nil {
					log.Println(err)
				}
				log.Printf("%v", r.pdu)
			}()
		}
	}
}

func socket() *ipv4.PacketConn {
	c, err := net.ListenPacket("udp4", "0.0.0.0:520")
	if err != nil {
		log.Fatal(err)
	}
	// defer c.Close()
	p := ipv4.NewPacketConn(c)

	br0, err := net.InterfaceByName("br0")
	if err != nil {
		log.Fatal(err)
	}

	mrip := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	if err := p.JoinGroup(br0, &mrip); err != nil {
		log.Fatal(err)
	}
	// defer p.LeaveGroup(br0, &mrip)
	if err := p.SetControlMessage(ipv4.FlagDst, true); err != nil {
		log.Fatal(err)
	}

	return p
}
