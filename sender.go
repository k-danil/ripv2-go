package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"time"
)

func (pdu *pdu) toByte(KeyChain keyChain) []byte {
	if sys.config.Global.Log == 5 {
		sys.logger.send(debug, pdu)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pdu.header)

	switch KeyChain.AuthType {
	case authPlain:
		plain := authKeyEntry{
			AFI:      afiAuth,
			AuthType: authPlain,
			Key:      padKey(KeyChain.AuthKey),
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

	if KeyChain.AuthType == authHash {
		key := authKeyEntry{
			AFI:      afiAuth,
			AuthType: authKey,
			Key:      padKey(KeyChain.AuthKey),
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

func sendPduAll(pds []*pdu) {
	for _, pdu := range pds {
		if pdu.serviceFields.ifi != 0 {
			ifi := pdu.serviceFields.ifi
			sys.socket.sendMcast(pdu.toByte(sys.config.Interfaces[ifi].KeyChain), ifi)
		} else if pdu.serviceFields.ip != 0 {
			ip := pdu.serviceFields.ip
			sys.socket.sendUcast(pdu.toByte(sys.config.Neighbors[ip].KeyChain), uintToIP(ip))
		}
	}
}

func reqGiveAll() {
	pds := make([]*pdu, 0)
	pduTemp := pdu{
		header:       header{Command: request, Version: 2},
		routeEntries: []routeEntry{{Metric: infMetric}},
	}

	for ip := range sys.config.Neighbors {
		pdu := pduTemp
		pdu.serviceFields = serviceFields{ip: ip}

		pds = append(pds, &pdu)
	}
	for ifi, opt := range sys.config.Interfaces {
		if opt.Passive {
			continue
		}
		pdu := pduTemp
		pdu.serviceFields = serviceFields{ifi: ifi}

		pds = append(pds, &pdu)
	}

	sendPduAll(pds)
}

func (a *adjTable) respToGive(p *pdu) {
	pds := make([]*pdu, 0)

	if _, ok := sys.config.Neighbors[p.serviceFields.ip]; ok {
		pds = a.pduPerIP(!change, p.serviceFields.ip)
		sendPduAll(pds)
	} else {
		pds = a.pduPerIfi(!change, p.serviceFields.ifi)
		sendPduAll(pds)
	}
}

func (a *adjTable) respToReq(p *pdu) {
	for _, pEnt := range p.routeEntries {
		netid := ipNet{ip: pEnt.Network, mask: pEnt.Mask}
		if a.entries[netid] == nil {
			pEnt.Metric = infMetric
		} else {
			pEnt.Metric = a.entries[netid].metric
		}
	}
	ip := p.serviceFields.ip
	sys.socket.sendUcast(p.toByte(sys.config.Neighbors[ip].KeyChain), uintToIP(ip))
}

func (a *adjTable) respUpdate(change bool) {
	pds := make([]*pdu, 0)

	for ip := range sys.config.Neighbors {
		pds = append(pds, a.pduPerIP(change, ip)...)
	}
	for ifi, opt := range sys.config.Interfaces {
		if opt.Passive {
			continue
		}
		pds = append(pds, a.pduPerIfi(change, ifi)...)
	}

	sendPduAll(pds)

	if change {
		a.cleanChangeFlag()
	}
}

func (a *adjTable) pduPerIfi(change bool, ifi int) []*pdu {
	pds := make([]*pdu, 0)
	size := sys.config.Global.MsgSize

	if sys.config.Interfaces[ifi].KeyChain.AuthType > 0 {
		size -= int(sys.config.Interfaces[ifi].KeyChain.AuthType - 1)
	}
	filter := func(a *adj) bool { return a.ifi != ifi }
	filtered := a.filterBy(filter, change)
	service := serviceFields{ifi: ifi}
	return append(pds, limitPduSize(size, filtered, service)...)

}
func (a *adjTable) pduPerIP(change bool, ip uint32) []*pdu {
	pds := make([]*pdu, 0)
	size := sys.config.Global.MsgSize

	if sys.config.Neighbors[ip].KeyChain.AuthType > 0 {
		size -= int(sys.config.Neighbors[ip].KeyChain.AuthType - 1)
	}
	filter := func(a *adj) bool { return a.nextHop != ip }
	filtered := a.filterBy(filter, change)
	service := serviceFields{ip: ip}
	return append(pds, limitPduSize(size, filtered, service)...)
}

func (a *adjTable) filterBy(filter func(a *adj) bool, change bool) []routeEntry {
	a.mux.Lock()
	defer a.mux.Unlock()
	filtered := make([]routeEntry, 0)

	for net, opt := range a.entries {
		if change {
			if change != opt.change {
				continue
			}
		}
		if filter(opt) {
			routeEntry := routeEntry{
				Network: net.ip,
				Mask:    net.mask,
				Metric:  opt.metric,
				AFI:     afiIPv4,
			}
			filtered = append(filtered, routeEntry)
		}
	}
	return filtered
}

func limitPduSize(size int, entList []routeEntry, service serviceFields) []*pdu {
	count := (len(entList) / size) + 1
	pds := make([]*pdu, count)

	for i := 0; i < count; i++ {
		pds[i] = &pdu{
			serviceFields: service,
			header:        header{Command: response, Version: 2},
		}
	}
	for pos, ent := range entList {
		pds[pos/size].routeEntries = append(pds[pos/size].routeEntries, ent)
	}
	return pds
}

func (pdu *pdu) makeAuth() {

}
