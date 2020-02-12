package main

import (
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

func main() {

	interfaces := []string{"br0"}
	pass := "123"

	//Listen for multicast on interfaces
	p := socket(interfaces)
	defer socketClose(p, interfaces)

	//Receive packet in buffer
	for {
		b := make([]byte, 504) //Maximum size of RIP pdu - 504byte
		s, cm, _, err := p.ReadFrom(b)
		if err != nil {
			log.Fatal(err)
		} else if s != 0 {
			//Process received packet
			go func() {
				//Fill service fields and payload to struct
				r, err := read(b[:s], cm.IfIndex, cm.Src)
				if err != nil {
					log.Fatal(err)
				}
				//Parse payload
				r.parser()
				//Validate over RFC guidline and authenticate with pass
				err = r.validator(pass)
				if err != nil {
					log.Println(err)
				}
				log.Printf("%v", r.pdu)
			}()
		}
	}
}

func socket(ifcn []string) *ipv4.PacketConn {
	mrip := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	c, err := net.ListenPacket("udp4", "0.0.0.0:520")
	if err != nil {
		log.Fatal(err)
	}

	p := ipv4.NewPacketConn(c)

	for _, ifc := range ifcn {
		ifi, err := net.InterfaceByName(ifc)
		if err != nil {
			log.Fatal(err)
		}
		if err := p.JoinGroup(ifi, &mrip); err != nil {
			log.Fatal(err)
		}
	}

	if err := p.SetControlMessage(ipv4.FlagDst, true); err != nil {
		log.Fatal(err)
	}

	return p
}

func socketClose(p *ipv4.PacketConn, ifcn []string) {
	mrip := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	for _, ifc := range ifcn {
		ifi, err := net.InterfaceByName(ifc)
		if err != nil {
			log.Fatal(err)
		}
		p.LeaveGroup(ifi, &mrip)
	}
	p.Close()
}
