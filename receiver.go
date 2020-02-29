package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"
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
	ifn     string
	content []byte
}

type pdu struct {
	serviceFields serviceFields
	header        header
	routeEntries  []routeEntry
	auth          bool
	authType      uint16
	authEntry     authHashEntry
	authKeyEntry  []byte
}

type header struct {
	command uint8
	version uint8
	rd      uint16
}

type routeEntry struct {
	afi      uint16
	routeTag uint16
	network  uint32
	mask     uint32
	nextHop  uint32
	metric   uint32
}

type authHashEntry struct {
	afi      uint16
	authType uint16
	packLng  uint16
	keyID    uint8
	authLng  uint8
	sqn      uint32
	blank0   uint64
}

type serviceFields struct {
	ip        uint32
	ifn       string
	timestamp int64
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
	pdu := &pdu{
		serviceFields: serviceFields{
			ip:        binary.BigEndian.Uint32(p.src),
			ifn:       p.ifn,
			timestamp: time.Now().Unix(),
		},
		header: header{
			command: uint8(p.content[0]),
			version: uint8(p.content[1]),
			rd:      binary.BigEndian.Uint16(p.content[2:4]),
		},
	}

	for i := 1; i <= (len(p.content) / 20); i++ {
		offset := p.content[(i-1)*20+4 : i*20+4]
		afi := binary.BigEndian.Uint16(offset[0:2])
		if i == 1 {
			pdu.authType = binary.BigEndian.Uint16(offset[2:4])
		}
		switch afi {
		case afiAuth:
			pdu.auth = true
			authType := binary.BigEndian.Uint16(offset[2:4])
			switch authType {
			case authKey:
				pdu.authKeyEntry = offset[4:pdu.authEntry.authLng]
			case authPlain:
				pdu.authKeyEntry = bytes.TrimRight(offset[4:20], "\x00")
			case authHash:
				pdu.authEntry = authHashEntry{
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
			pdu.routeEntries = append(pdu.routeEntries, routeEntry)
		case afiGiveAll:
			routeEntry := routeEntry{
				afi:     afi,
				network: binary.BigEndian.Uint32(offset[4:8]),
				metric:  binary.BigEndian.Uint32(offset[16:20]),
			}
			pdu.routeEntries = append(pdu.routeEntries, routeEntry)
		}
	}

	return pdu
}

func (p *pdu) validate(conf *config, content []byte) error {
	if p.header.version != 2 {
		return errors.New("Incorrect RIP version (use 2)")
	}

	if p.auth {
		if conf.Interfaces[p.serviceFields.ifn].Auth {
			if p.authType != conf.Interfaces[p.serviceFields.ifn].KeyChain.AuthType {
				return errors.New("Incorrect AuthType")
			}

			switch p.authType {
			case authPlain:
				err := p.authPlain(conf.Interfaces[p.serviceFields.ifn].KeyChain.AuthKey)
				if err != nil {
					return err
				}
			case authHash:
				err := p.authHash(conf.Interfaces[p.serviceFields.ifn].KeyChain.AuthKey, content)
				if err != nil {
					return err
				}
			}
		} else {
			return errors.New("Authentication is not configured on interface")
		}
	} else {
		if conf.Interfaces[p.serviceFields.ifn].Auth {
			return errors.New("Expect authenticated packet on interface")
		}
	}

	if p.header.command == response {
		for l := 0; l < len(p.routeEntries); l++ {
			if p.routeEntries[l].metric > infMetric {
				p.routeEntries[l].metric = invMetric
				log.Printf("Bad metric. Route entry %v marked invalid.", uintToIP(p.routeEntries[l].network))
			} else if p.routeEntries[l].network != 0 && !net.IP(uintToIP(p.routeEntries[l].network)).IsGlobalUnicast() {
				p.routeEntries[l].metric = invMetric
				log.Printf("Bad address. Route entry %v marked invalid.", uintToIP(p.routeEntries[l].network))
			}
		}
	}
	return nil
}

func (p *pdu) authPlain(pass string) error {
	if string(p.authKeyEntry) != pass {
		return errors.New("Unauthenticated plain pass pdu")
	}
	return nil
}

func (p *pdu) authHash(pass string, content []byte) error {
	pa := padKey(pass, len(p.authKeyEntry))

	offset := p.authEntry.packLng + 4
	tcont := make([]byte, 0)
	tcont = append(tcont, content[:offset]...)
	tcont = append(tcont, pa...)
	hash := md5.Sum(tcont)

	if !bytes.Equal(hash[:], p.authKeyEntry) {
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
