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
		plain := authKeyEntry{
			AFI:      afiAuth,
			AuthType: authPlain,
			Key:      padKey(sys.config.Interfaces[ifn].KeyChain.AuthKey),
		}
		binary.Write(buf, binary.BigEndian, plain)
	case authHash:
		hash := authHashEntry{
			AFI:      afiAuth,
			AuthType: authHash,
			PackLng:  uint16(24 + (len(pdu.routeEntries) * 20)),
			KeyID:    1,
			AuthLng:  20,
			SQN:      uint32(time.Now().Unix()),
		}
		binary.Write(buf, binary.BigEndian, hash)
	}

	binary.Write(buf, binary.BigEndian, pdu.routeEntries)

	if sys.config.Interfaces[ifn].KeyChain.AuthType == authHash {
		key := authKeyEntry{
			AFI:      afiAuth,
			AuthType: authKey,
			Key:      padKey(sys.config.Interfaces[ifn].KeyChain.AuthKey),
		}
		binary.Write(buf, binary.BigEndian, key)
		hash := md5.Sum(buf.Bytes())
		buf.Truncate(28 + (len(pdu.routeEntries) * 20))
		binary.Write(buf, binary.BigEndian, hash)
	}

	return buf.Bytes()
}

func padKey(key string) [16]byte {
	var arr [16]byte
	k := key
	for l := 0; l < (16 - len(key)); l++ {
		k += "\x00"
	}
	copy(arr[:], k)
	return arr
}
