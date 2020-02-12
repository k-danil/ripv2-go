package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type pdu struct {
	header map[string][]byte
	entry  []map[string][]byte
}

type packet struct {
	src     net.IP
	ifi     int
	content []byte
	pdu     pdu
}

func read(content []byte, ifIndex int, src net.IP) (*packet, error) {
	p := &packet{src: src, ifi: ifIndex, content: content}
	if (len(content)-4)%20 != 0 {
		return nil, errors.New("Incorrect PDU size")
	}
	return p, nil
}

func (p *packet) parser() {
	p.pdu.header = map[string][]byte{
		"command": p.content[:1],
		"version": p.content[1:2],
	}
	entry := make([]map[string][]byte, 0)
	for i := 1; i <= (len(p.content) / 20); i++ {
		sEnt := p.content[(i-1)*20+4 : i*20+4]
		if binary.BigEndian.Uint16(sEnt[0:2]) == uint16(65535) {
			fiEnt := map[string][]byte{
				"afi":      sEnt[:2],
				"authType": sEnt[2:4],
			}
			if fiEnt["authType"][1] == byte(3) {
				fiEnt["packLng"] = sEnt[4:6]
				fiEnt["keyID"] = sEnt[6:7]
				fiEnt["authLng"] = sEnt[7:8]
				fiEnt["sqn"] = sEnt[8:12]
			} else {
				fiEnt["auth"] = sEnt[4:20]
			}

			entry = append(entry, fiEnt)
		} else {
			fiEnt := map[string][]byte{
				"afi":    sEnt[:2],
				"rt":     sEnt[2:4],
				"ip":     sEnt[4:8],
				"mask":   sEnt[8:12],
				"nh":     sEnt[12:16],
				"metric": sEnt[16:20],
			}

			entry = append(entry, fiEnt)
		}

	}
	p.pdu.entry = entry
}

func (p *packet) validator(pass string) error {
	if p.pdu.header["version"][0] != byte(2) {
		return errors.New("Incorrect RIP version (use 2)")
	}
	fmt.Println(len(p.pdu.entry))
	for l := 0; l < len(p.pdu.entry); l++ {
		//TODO authentication method
		if binary.BigEndian.Uint16(p.pdu.entry[l]["afi"]) == uint16(65535) {
			if binary.BigEndian.Uint16(p.pdu.entry[l]["authType"]) == uint16(2) {
				err := p.authPlain(pass)
				if err != nil {
					return err
				}
			} else if binary.BigEndian.Uint16(p.pdu.entry[l]["authType"]) == uint16(3) {
				err := p.authMD5(pass)
				if err != nil {
					return err
				}
			} else {
				return errors.New("Wrong auth method")
			}
		}

		ip := net.IP(p.pdu.entry[l]["ip"])
		//TODO remove and trim for broken entry
		if binary.BigEndian.Uint16(p.pdu.entry[l]["metric"]) > uint16(16) {
			return errors.New("Bad metric")
		} else if !ip.IsGlobalUnicast() {
			return errors.New("Bad address")
		}
	}
	return nil
}

func (p *packet) authPlain(pass string) error {
	if len(pass) > len(p.pdu.entry[0]["auth"]) {
		return errors.New("Configured pass longer then 16byte")
	}
	if string(p.pdu.entry[0]["auth"]) != pass {
		return errors.New("Unautorized pdu")
	}
	return nil
}
func (p *packet) authMD5(pass string) error {
	return nil
}
