package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"time"
)

type keyAuth struct {
	afi      uint16
	authType uint16
}

func (pdu *pdu) pduToByte(c *config) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pdu.header)

	if c.Interfaces[pdu.serviceFields.ifn].Auth {
		switch c.Interfaces[pdu.serviceFields.ifn].KeyChain.AuthType {
		case authPlain:
			pass := padKey(c.Interfaces[pdu.serviceFields.ifn].KeyChain.AuthKey, 16)
			plain := keyAuth{
				afi:      afiAuth,
				authType: authPlain,
			}
			binary.Write(buf, binary.BigEndian, plain)
			binary.Write(buf, binary.BigEndian, []byte(pass))
		case authHash:
			ctime := time.Now().Unix()
			hash := authHashEntry{
				afi:      afiAuth,
				authType: authHash,
				packLng:  uint16(24 + (len(pdu.routeEntries) * 20)),
				keyID:    1,
				authLng:  16,
				sqn:      uint32(ctime),
			}
			binary.Write(buf, binary.BigEndian, hash)
		}
	}

	for _, rEnt := range pdu.routeEntries {
		binary.Write(buf, binary.BigEndian, rEnt)
	}

	if c.Interfaces[pdu.serviceFields.ifn].Auth && c.Interfaces[pdu.serviceFields.ifn].KeyChain.AuthType == authHash {
		pass := padKey(c.Interfaces[pdu.serviceFields.ifn].KeyChain.AuthKey, 16)
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

func padKey(key string, size int) string {
	k := key
	for l := 0; l < (size - len(key)); l++ {
		k += "\x00"
	}
	return k
}
