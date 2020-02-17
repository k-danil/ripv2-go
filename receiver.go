package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"net"
)

const (
	authKey   uint16 = 1
	authPlain uint16 = 2
	authHash  uint16 = 3
)

const (
	afiAuth    uint16 = 65535
	afiIPv4    uint16 = 2
	afiGiveAll uint16 = 0
)

type packet struct {
	src     net.IP
	ifi     int
	content []byte
	pdu     pdu
}

type pdu struct {
	serviceFields serviceFields
	header        header
	routeEntries  []routeEntry
	authType      uint16
	authEntry     authEntry
	authKeyEntry  []byte
	invalid       bool
}

type header struct {
	command uint8
	version uint8
	rd      uint16
}

type routeEntry struct {
	network  uint32
	mask     uint32
	nextHop  uint32
	metric   uint32
	afi      uint16
	routeTag uint16
	invalid  bool
}

type authEntry struct {
	packLng uint16
	keyID   uint8
	authLng uint8
	sqn     uint32
}

type serviceFields struct {
	srcIP uint32
	srcIf uint16
}

func read(content []byte, ifIndex int, src net.IP) (*packet, error) {
	p := &packet{src: src, ifi: ifIndex, content: content}
	return p, nil
}

func (p *packet) parser() {
	p.pdu.serviceFields = serviceFields{
		srcIP: binary.BigEndian.Uint32(p.src),
		srcIf: uint16(p.ifi),
	}
	p.pdu.header = header{
		command: uint8(p.content[0]),
		version: uint8(p.content[1]),
		rd:      binary.BigEndian.Uint16(p.content[2:4]),
	}
	for i := 1; i <= (len(p.content) / 20); i++ {
		offset := p.content[(i-1)*20+4 : i*20+4]
		afi := binary.BigEndian.Uint16(offset[0:2])
		if i == 1 {
			p.pdu.authType = binary.BigEndian.Uint16(offset[2:4])
		}
		switch afi {
		case afiAuth:
			authType := binary.BigEndian.Uint16(offset[2:4])
			switch authType {
			case authKey:
				p.pdu.authKeyEntry = offset[4:p.pdu.authEntry.authLng]
			case authPlain:
				p.pdu.authKeyEntry = bytes.TrimRight(offset[4:20], "\x00")
			case authHash:
				p.pdu.authEntry = authEntry{
					packLng: binary.BigEndian.Uint16(offset[4:6]),
					keyID:   uint8(offset[6]),
					authLng: uint8(offset[7]),
					sqn:     binary.BigEndian.Uint32(offset[8:12]),
				}
			}
		case afiIPv4:
			routeEntry := routeEntry{
				afi:      afi,
				routeTag: binary.BigEndian.Uint16(offset[2:4]),
				network:  binary.BigEndian.Uint32(offset[4:8]),
				mask:     binary.BigEndian.Uint32(offset[8:12]),
				nextHop:  binary.BigEndian.Uint32(offset[12:16]),
				metric:   binary.BigEndian.Uint32(offset[16:20]),
			}
			p.pdu.routeEntries = append(p.pdu.routeEntries, routeEntry)
		case afiGiveAll:
			routeEntry := routeEntry{
				afi:     afi,
				network: binary.BigEndian.Uint32(offset[4:8]),
				metric:  binary.BigEndian.Uint32(offset[16:20]),
			}
			p.pdu.routeEntries = append(p.pdu.routeEntries, routeEntry)
		}

	}
}

func (p *packet) validator(pass string) (*pdu, error) {
	if p.pdu.header.version != 2 {
		return nil, errors.New("Incorrect RIP version (use 2)")
	}
	switch p.pdu.authType {
	case authPlain:
		err := p.authPlain(pass)
		if err != nil {
			return nil, err
		}
	case authHash:
		err := p.authHash(pass)
		if err != nil {
			return nil, err
		}
	}
	if p.pdu.header.command == response {
		for l := 0; l < len(p.pdu.routeEntries); l++ {
			if p.pdu.routeEntries[l].metric > 16 {
				p.pdu.routeEntries[l].invalid = true
				return nil, errors.New("Bad metric")
			} else if net.IP(uintToIP(p.pdu.routeEntries[l].network)).IsLoopback() {
				p.pdu.routeEntries[l].invalid = true
				return nil, errors.New("Bad address")
			}
		}
	}

	pdu := &p.pdu

	return pdu, nil
}

func (p *packet) authPlain(pass string) error {
	if string(p.pdu.authKeyEntry) != pass {
		p.pdu.invalid = true
		return errors.New("Unauthenticated plain pass pdu")
	}
	return nil
}

func (p *packet) authHash(pass string) error {
	pa := pass
	for l := 0; l < (len(p.pdu.authKeyEntry) - len(pass)); l++ {
		pa += "\x00"
	}

	offset := p.pdu.authEntry.packLng + 4
	tcont := make([]byte, 0)
	tcont = append(tcont, p.content[:offset]...)
	tcont = append(tcont, pa...)
	hash := md5.Sum(tcont)

	if !bytes.Equal(hash[:], p.pdu.authKeyEntry) {
		p.pdu.invalid = true
		return errors.New("Unauthenticated md5 pdu")
	}
	return nil
}

func uintToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result
}
