package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"time"
)

func (pdu *pdu) pduToByte() []byte {
	if sys.config.Local.Log == 5 {
		sys.logger.send(debug, pdu)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pdu.header)
	ifn := pdu.serviceFields.ifn

	switch sys.config.Interfaces[ifn].KeyChain.AuthType {
	case authPlain:
		pass := padKey(sys.config.Interfaces[ifn].KeyChain.AuthKey, 16)
		plain := authKeyEntry{
			afi:      afiAuth,
			authType: authPlain,
		}
		binary.Write(buf, binary.BigEndian, plain)
		binary.Write(buf, binary.BigEndian, []byte(pass))
	case authHash:
		hash := authHashEntry{
			afi:      afiAuth,
			authType: authHash,
			packLng:  uint16(24 + (len(pdu.routeEntries) * 20)),
			keyID:    1,
			authLng:  16,
			sqn:      uint32(time.Now().Unix()),
		}
		binary.Write(buf, binary.BigEndian, hash)
	}

	binary.Write(buf, binary.BigEndian, pdu.routeEntries)

	if sys.config.Interfaces[ifn].KeyChain.AuthType == authHash {
		pass := padKey(sys.config.Interfaces[ifn].KeyChain.AuthKey, 16)
		key := authKeyEntry{
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
