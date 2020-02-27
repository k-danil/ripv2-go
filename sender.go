package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

type keyAuth struct {
	afi      uint16
	authType uint16
}

type hashAuth struct {
	afi      uint16
	authType uint16
	packLng  uint16
	keyID    uint8
	authLng  uint8
	sqn      uint32
	blank0   uint64
}

// func (pdu *pdu) pduToPacket(c *config, ifn string) {
// 	// log.Printf("%+v", pdu)
// 	pdu.pduToByte(c, ifn)
// }

func (pdu *pdu) pduToByte(c *config, ifn string) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pdu.header)

	if c.Interfaces[ifn].Auth {
		switch c.Interfaces[ifn].KeyChain.AuthType {
		case authPlain:
			pass := c.Interfaces[ifn].KeyChain.AuthKey
			for l := 0; l < 16; l++ {
				pass += "\x00"
			}
			plain := keyAuth{
				afi:      afiAuth,
				authType: authPlain,
			}
			binary.Write(buf, binary.BigEndian, plain)
			binary.Write(buf, binary.BigEndian, []byte(pass))
		case authHash:
			ctime := time.Now().Unix()
			hash := hashAuth{
				afi:      afiAuth,
				authType: authHash,
				packLng:  uint16(24 + (len(pdu.routeEntries) * 20)),
				keyID:    1,
				authLng:  20,
				sqn:      uint32(ctime),
			}
			binary.Write(buf, binary.BigEndian, hash)
		}
	}

	for _, rEnt := range pdu.routeEntries {
		binary.Write(buf, binary.BigEndian, rEnt)
	}

	if c.Interfaces[ifn].Auth && c.Interfaces[ifn].KeyChain.AuthType == authHash {
		pass := c.Interfaces[ifn].KeyChain.AuthKey
		for l := 0; l < 16; l++ {
			pass += "\x00"
		}
		key := keyAuth{
			afi:      afiAuth,
			authType: authKey,
		}
		binary.Write(buf, binary.BigEndian, key)
		binary.Write(buf, binary.BigEndian, []byte(pass))
		hash := md5.Sum(buf.Bytes())
		buf.Truncate(28 + (len(pdu.routeEntries) * 20))
		binary.Write(buf, binary.BigEndian, hash)
	}

	return buf.Bytes()
}

func sendToSocket(p *ipv4.PacketConn, data []byte, ifn string) {
	group := net.IPv4(224, 0, 0, 9)
	dst := &net.UDPAddr{IP: group, Port: 520}
	ifi, _ := net.InterfaceByName(ifn)
	if err := p.SetMulticastInterface(ifi); err != nil {
		// error handling
	}
	p.SetMulticastTTL(2)
	if _, err := p.WriteTo(data, nil, dst); err != nil {
		// error handling
	}
}
