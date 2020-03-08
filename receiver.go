package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	authNon   uint16 = 0
	authKey   uint16 = 1
	authPlain uint16 = 2
	authHash  uint16 = 3
)

const (
	afiAuth    uint16 = 0xffff
	afiIPv4    uint16 = 2
	afiGiveAll uint16 = 0
)

type packet struct {
	src     net.IP
	ifn     string
	content []byte
}

type pdu struct {
	serviceFields serviceFields
	header        header
	routeEntries  []routeEntry
	authHashEntry authHashEntry
	authKeyEntry  authKeyEntry
}

type header struct {
	Command uint8
	Version uint8
	RD      uint16
}

type routeEntry struct {
	AFI      uint16
	RouteTag uint16
	Network  uint32
	Mask     uint32
	NextHop  uint32
	Metric   uint32
}

type authHashEntry struct {
	AFI      uint16
	AuthType uint16
	PackLng  uint16
	KeyID    uint8
	AuthLng  uint8
	SQN      uint32
	Blank0   uint64
}

type authKeyEntry struct {
	AFI      uint16
	AuthType uint16
	Key      [16]byte
}

type serviceFields struct {
	ip        uint32
	ifn       string
	timestamp int64
	authType  uint16
}

func readPacket(content []byte, ifName string, src net.IP) (*packet, error) {
	if val, _ := isLocalAddress(src); val {
		return nil, errors.New("Loop")
	}

	p := &packet{
		src:     src,
		ifn:     ifName,
		content: content,
	}

	return p, nil
}

func (p *packet) parse() *pdu {
	buf := bytes.NewBuffer(p.content)

	pdu := &pdu{
		serviceFields: serviceFields{
			ip:        binary.BigEndian.Uint32(p.src),
			ifn:       p.ifn,
			timestamp: time.Now().Unix(),
		},
	}

	binary.Read(buf, binary.BigEndian, &pdu.header)

	for buf.Len() > 0 {
		afi := binary.BigEndian.Uint16(buf.Bytes()[:2])
		switch afi {
		case afiAuth:
			authType := binary.BigEndian.Uint16(buf.Bytes()[2:4])
			switch authType {
			case authKey:
				binary.Read(buf, binary.BigEndian, &pdu.authKeyEntry)
			case authPlain:
				binary.Read(buf, binary.BigEndian, &pdu.authKeyEntry)
				pdu.serviceFields.authType = authType
			case authHash:
				binary.Read(buf, binary.BigEndian, &pdu.authHashEntry)
				pdu.serviceFields.authType = authType
			}
		case afiIPv4:
			if pdu.serviceFields.authType == authHash {
				pdu.routeEntries = make([]routeEntry, buf.Len()/20-1)
			} else {
				pdu.routeEntries = make([]routeEntry, buf.Len()/20)
			}
			binary.Read(buf, binary.BigEndian, &pdu.routeEntries)
		case afiGiveAll:
			routeEntry := routeEntry{}
			binary.Read(buf, binary.BigEndian, &routeEntry)
			pdu.routeEntries = append(pdu.routeEntries, routeEntry)
		}
	}

	return pdu
}

func (p *pdu) validate(content []byte, keyChain keyChain) error {
	if p.header.Version != 2 {
		return errors.New("Incorrect RIP version (use 2)")
	}

	if p.serviceFields.authType == keyChain.AuthType {
		switch p.serviceFields.authType {
		case authPlain:
			err := p.authPlain(keyChain.AuthKey)
			if err != nil {
				return err
			}
		case authHash:
			err := p.authHash(keyChain.AuthKey, content)
			if err != nil {
				return err
			}
		}
	} else {
		return errors.New("Incorrect AuthType")
	}

	if p.header.Command == response {
		for l := 0; l < len(p.routeEntries); l++ {
			if p.routeEntries[l].Metric > infMetric {
				p.routeEntries[l].Metric = invMetric
				sys.logger.send(warn, fmt.Sprintf("Bad metric. Route entry %v marked invalid.", uintToIP(p.routeEntries[l].Network)))
			} else if p.routeEntries[l].Network != 0 && !net.IP(uintToIP(p.routeEntries[l].Network)).IsGlobalUnicast() {
				p.routeEntries[l].Metric = invMetric
				sys.logger.send(warn, fmt.Sprintf("Bad address. Route entry %v marked invalid.", uintToIP(p.routeEntries[l].Network)))
			}
		}
	}
	return nil
}

func (p *pdu) authPlain(pass string) error {
	if p.authKeyEntry.Key != padKey(pass) {
		return errors.New("Unauthenticated plain pass pdu")
	}
	return nil
}

func (p *pdu) authHash(pass string, content []byte) error {
	key := padKey(pass)

	tcont := make([]byte, 0, p.authHashEntry.PackLng+20)
	tcont = append(tcont, content[:p.authHashEntry.PackLng+4]...)
	tcont = append(tcont, key[:]...)

	if md5.Sum(tcont) != p.authKeyEntry.Key {
		return errors.New("Unauthenticated md5 pdu")
	}
	return nil
}

func uintToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	result[3] = byte(ip)
	result[2] = byte(ip >> 8)
	result[1] = byte(ip >> 16)
	result[0] = byte(ip >> 24)

	return result
}
