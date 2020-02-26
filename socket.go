package main

import (
	"log"
	"net"

	"golang.org/x/net/ipv4"
)

func socket(conf *config) *ipv4.PacketConn {
	mrip := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	c, err := net.ListenPacket("udp4", "0.0.0.0:520")
	if err != nil {
		log.Fatal(err)
	}

	p := ipv4.NewPacketConn(c)

	for ifc := range conf.Interfaces {
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

func socketClose(p *ipv4.PacketConn, conf *config) {
	mrip := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	for ifc := range conf.Interfaces {
		ifi, err := net.InterfaceByName(ifc)
		if err != nil {
			log.Fatal(err)
		}
		p.LeaveGroup(ifi, &mrip)
	}
	p.Close()
}
