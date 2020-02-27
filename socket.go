package main

import (
	"net"

	"golang.org/x/net/ipv4"
)

func socketOpen(c *config) (*ipv4.PacketConn, error) {
	mrip := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	s, err := net.ListenPacket("udp4", "0.0.0.0:520")
	if err != nil {
		return nil, err
	}

	p := ipv4.NewPacketConn(s)

	for ifc := range c.Interfaces {
		ifi, err := net.InterfaceByName(ifc)
		if err != nil {
			return nil, err
		}
		if err := p.JoinGroup(ifi, &mrip); err != nil {
			return nil, err
		}
	}

	if err := p.SetControlMessage(ipv4.FlagDst, true); err != nil {
		return nil, err
	}

	return p, nil
}

func socketClose(p *ipv4.PacketConn, c *config) error {
	mrip := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	for ifc := range c.Interfaces {
		ifi, err := net.InterfaceByName(ifc)
		if err != nil {
			return err
		}
		p.LeaveGroup(ifi, &mrip)
	}
	p.Close()

	return nil
}
