package main

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
)

type socket struct {
	mux     sync.Mutex
	connect *ipv4.PacketConn
	config  *config
}

func socketOpen(c *config) (*socket, error) {
	s, err := net.ListenPacket("udp4", "0.0.0.0:520")
	if err != nil {
		return nil, err
	}

	p := ipv4.NewPacketConn(s)

	if err := p.SetControlMessage(ipv4.FlagDst, true); err != nil {
		return nil, err
	}

	socket := &socket{
		connect: p,
		config:  c,
	}

	return socket, nil
}

func (s *socket) socketJoinMcast() error {
	group := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	for ifc := range s.config.Interfaces {
		ifi, err := net.InterfaceByName(ifc)
		if err != nil {
			return err
		}
		if err := s.connect.JoinGroup(ifi, &group); err != nil {
			return err
		}
	}
	return nil
}

func (s *socket) socketLeaveMcast() error {
	group := net.UDPAddr{IP: net.IPv4(224, 0, 0, 9)}

	for ifc := range s.config.Interfaces {
		ifi, err := net.InterfaceByName(ifc)
		if err != nil {
			return err
		}
		s.connect.LeaveGroup(ifi, &group)
	}
	return nil
}

func (s *socket) socketClose() error {
	if err := s.socketLeaveMcast(); err != nil {
		return err
	}
	s.connect.Close()

	return nil
}

func (s *socket) socketSendMcast(data []byte, ifn string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	dst := &net.UDPAddr{IP: net.IPv4(224, 0, 0, 9), Port: 520}
	s.connect.SetTOS(0xc0)

	ifi, _ := net.InterfaceByName(ifn)
	if err := s.connect.SetMulticastInterface(ifi); err != nil {
		return err
	}
	s.connect.SetMulticastTTL(1)
	if _, err := s.connect.WriteTo(data, nil, dst); err != nil {
		return err
	}
	return nil
}
