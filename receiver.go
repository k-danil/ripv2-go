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
	entrySize  = 20
	headerSize = 4
)

const (
	authNon   = 0
	authKey   = 1
	authPlain = 2
	authHash  = 3
)

const (
	afiAuth    = 0xffff
	afiIPv4    = 2
	afiGiveAll = 0
)

type packet struct {
	src     uint32
	ifi     int
	content []byte
}

type pdu struct {
	serviceFields *serviceFields
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
	_        uint64
}

type authKeyEntry struct {
	AFI      uint16
	AuthType uint16
	Key      [16]byte
}

type serviceFields struct {
	ip        uint32
	authType  uint16
	ifi       int
	timestamp int64
}

func readPacket(content []byte, ifi int, src uint32) (*packet, error) {
	if val, _ := isLocal(src); val {
		return nil, errors.New("Loop")
	}

	if _, ok := sys.config.Interfaces[ifi]; !ok {
		if _, ok = sys.config.Neighbors[src]; !ok {
			return nil, errors.New("Packet with unspecified source")
		}
	}

	return &packet{
		src:     src,
		ifi:     ifi,
		content: content,
	}, nil
}

func (p *packet) parse() *pdu {
	buf := bytes.NewBuffer(p.content)

	pdu := &pdu{
		serviceFields: &serviceFields{
			ip:        p.src,
			ifi:       p.ifi,
			timestamp: time.Now().Unix(),
		},
	}

	binary.Read(buf, binary.BigEndian, &pdu.header)

	for buf.Len() > 0 {
		switch binary.BigEndian.Uint16(buf.Bytes()[:2]) {
		case afiAuth:
			switch binary.BigEndian.Uint16(buf.Bytes()[2:4]) {
			case authKey:
				binary.Read(buf, binary.BigEndian, &pdu.authKeyEntry)
			case authPlain:
				binary.Read(buf, binary.BigEndian, &pdu.authKeyEntry)
				pdu.serviceFields.authType = authPlain
			case authHash:
				binary.Read(buf, binary.BigEndian, &pdu.authHashEntry)
				pdu.serviceFields.authType = authHash
			}
		default:
			if pdu.serviceFields.authType == authHash {
				pdu.routeEntries = make([]routeEntry, buf.Len()/entrySize-1)
			} else {
				pdu.routeEntries = make([]routeEntry, buf.Len()/entrySize)
			}
			binary.Read(buf, binary.BigEndian, &pdu.routeEntries)
		}
	}
	return pdu
}

func (p *pdu) validate(keyChain keyChain) error {
	if p.header.Version != 2 {
		return errors.New("incorrect RIP version (use 2)")
	}

	if p.serviceFields.authType == keyChain.AuthType {
		switch p.serviceFields.authType {
		case authPlain:
			err := p.authPlain(keyChain.AuthKey)
			if err != nil {
				return err
			}
		case authHash:
			err := p.authHash(keyChain.AuthKey)
			if err != nil {
				return err
			}
		}
	} else {
		return errors.New("incorrect AuthType")
	}

	if p.header.Command == response {
		for l := 0; l < len(p.routeEntries); l++ {
			if p.routeEntries[l].Metric > infMetric {
				p.routeEntries[l].Metric = invMetric
				sys.logger.send(warn, fmt.Sprintf("route entry %v marked invalid", uintToIP(p.routeEntries[l].Network)))
			} else if p.routeEntries[l].Network != 0 && !uintToIP(p.routeEntries[l].Network).IsGlobalUnicast() {
				p.routeEntries[l].Metric = invMetric
				sys.logger.send(warn, fmt.Sprintf("route entry %v marked invalid", uintToIP(p.routeEntries[l].Network)))
			}
		}
	}
	return nil
}

func (p *pdu) authPlain(pass string) error {
	if p.authKeyEntry.Key != padKey(pass) {
		return errors.New("unauthenticated plain pass pdu")
	}
	return nil
}

func (p *pdu) authHash(pass string) error {
	key := p.authKeyEntry.Key
	p.authKeyEntry.Key = padKey(pass)
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, p.header)
	binary.Write(buf, binary.BigEndian, p.authHashEntry)
	binary.Write(buf, binary.BigEndian, p.routeEntries)
	binary.Write(buf, binary.BigEndian, p.authKeyEntry)

	if md5.Sum(buf.Bytes()) != key {
		return errors.New("unauthenticated md5 pdu")
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
