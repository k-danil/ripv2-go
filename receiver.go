package main

import (
	"bytes"
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
	afiAuth uint16 = 65535
	afiIPv4 uint16 = 2
)

type pdu struct {
	header       header
	routeEntries []routeEntry
	authType     uint16
	authEntry    authEntry
	authKeyEntry []byte
	err          bool
}

type header struct {
	command uint8
	version uint8
	rd      uint16
}

type routeEntry struct {
	ip     uint32
	mask   uint32
	nh     uint32
	gw     uint32
	metric uint32
	afi    uint16
	rt     uint16
	err    bool
}

type authEntry struct {
	packLng uint16
	keyID   uint8
	authLng uint8
	sqn     uint32
}

type packet struct {
	src     net.IP
	ifi     int
	content []byte
	pdu     pdu
}

func read(content []byte, ifIndex int, src net.IP) (*packet, error) {
	p := &packet{src: src, ifi: ifIndex, content: content}
	return p, nil
}

func (p *packet) parser() {
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
				p.pdu.authKeyEntry = bytes.TrimRight(offset[4:30], "\x00")
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
				afi:    afi,
				rt:     binary.BigEndian.Uint16(offset[2:4]),
				ip:     binary.BigEndian.Uint32(offset[4:8]),
				mask:   binary.BigEndian.Uint32(offset[8:12]),
				nh:     binary.BigEndian.Uint32(offset[12:16]),
				metric: binary.BigEndian.Uint32(offset[16:20]),
			}
			p.pdu.routeEntries = append(p.pdu.routeEntries, routeEntry)
		}

	}
}

func (p *packet) validator(pass string) error {
	if p.pdu.header.version != 2 {
		return errors.New("Incorrect RIP version (use 2)")
	}
	switch p.pdu.authType {
	case authPlain:
		err := p.authPlain(pass)
		if err != nil {
			return err
		}
	case authHash:
		err := p.authHash(pass)
		if err != nil {
			return err
		}
	}
	for l := 0; l < len(p.pdu.routeEntries); l++ {
		if p.pdu.routeEntries[l].metric > 16 {
			p.pdu.routeEntries[l].err = true
			return errors.New("Bad metric")
		} else if !net.IP(uintToIP(p.pdu.routeEntries[l].ip)).IsGlobalUnicast() {
			p.pdu.routeEntries[l].err = true
			return errors.New("Bad address")
		}
	}

	return nil
}

func (p *packet) authPlain(pass string) error {
	if string(p.pdu.authKeyEntry) != pass {
		p.pdu.err = true
		return errors.New("Unauthenticated plain pass pdu")
	}
	return nil
}

func (p *packet) authHash(pass string) error {
	p.pdu.err = true
	return errors.New("Hash authentication not implemented yet")
}

func uintToIP(ip uint32) net.IP {
	result := make(net.IP, 4)
	result[0] = byte(ip)
	result[1] = byte(ip >> 8)
	result[2] = byte(ip >> 16)
	result[3] = byte(ip >> 24)
	return result
}
