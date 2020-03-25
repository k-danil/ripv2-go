package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"time"
)

var authEntries = map[uint16]int{
	0: 0,
	1: 0,
	2: 1,
	3: 2,
}

type filtFunc func(*adj) bool

func (p *pdu) toByte() []byte {
	if sys.config.Global.Log == debug {
		sys.logger.send(debug, p)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, p.header)

	switch p.serviceFields.authType {
	case authPlain:
		binary.Write(buf, binary.BigEndian, p.authKeyEntry)
	case authHash:
		binary.Write(buf, binary.BigEndian, p.authHashEntry)
	}

	binary.Write(buf, binary.BigEndian, p.routeEntries)

	if p.serviceFields.authType == authHash {
		binary.Write(buf, binary.BigEndian, p.authKeyEntry)
		hash := md5.Sum(buf.Bytes())
		buf.Truncate(int(p.authHashEntry.PackLng) + 4)
		binary.Write(buf, binary.BigEndian, hash)
	}

	return buf.Bytes()
}

func padKey(key string) (arr [16]byte) {
	i := len(key)
	if i > 15 {
		i = 15
	}
	for pos := range key[:i] {
		arr[pos] = key[pos]
	}
	return
}

func sendPduAll(pds []*pdu) {
	for _, pdu := range pds {
		if pdu.serviceFields.ifi != 0 {
			ifi := pdu.serviceFields.ifi
			pdu.makeAuth(sys.config.Interfaces[ifi].KeyChain.AuthKey)
			go sys.socket.sendMcast(pdu.toByte(), ifi)
		} else if pdu.serviceFields.ip != 0 {
			ip := pdu.serviceFields.ip
			pdu.makeAuth(sys.config.Neighbors[ip].KeyChain.AuthKey)
			go sys.socket.sendUcast(pdu.toByte(), uintToIP(ip))
		}
	}
}

func reqGiveAll() {
	pds := make([]*pdu, 0, 8)
	pduTemp := pdu{
		header:       header{Command: request, Version: 2},
		routeEntries: []routeEntry{{Metric: infMetric}},
	}

	for ip, opt := range sys.config.Neighbors {
		pdu := pduTemp
		pdu.serviceFields = &serviceFields{ip: ip, authType: opt.KeyChain.AuthType}

		pds = append(pds, &pdu)
	}
	for ifi, opt := range sys.config.Interfaces {
		if opt.Passive {
			continue
		}
		pdu := pduTemp
		pdu.serviceFields = &serviceFields{ifi: ifi, authType: opt.KeyChain.AuthType}

		pds = append(pds, &pdu)
	}

	sendPduAll(pds)
}

func (a *adjTable) respToGive(p *pdu) {
	pds := make([]*pdu, 0, 8)

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
		netid := ipNet{IP: pEnt.Network, Mask: pEnt.Mask}
		if a.entries[netid] == nil {
			pEnt.Metric = infMetric
		} else {
			pEnt.Metric = a.entries[netid].metric
		}
	}
	ip := p.serviceFields.ip
	p.makeAuth(sys.config.Neighbors[ip].KeyChain.AuthKey)
	sys.socket.sendUcast(p.toByte(), uintToIP(ip))
}

func (a *adjTable) respUpdate(change bool) {
	pds := make([]*pdu, 0, 8)

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
		a.clearChangeFlag()
	}
}

func (a *adjTable) pduPerIfi(change bool, ifi int) []*pdu {
	pds := make([]*pdu, 0, 8)
	service := &serviceFields{
		ifi:      ifi,
		authType: sys.config.Interfaces[ifi].KeyChain.AuthType,
	}

	filter := func(a *adj) bool { return a.ifi != ifi }
	filtered := a.filterBy(filter, change)
	return append(pds, limitPduSize(sys.config.Global.EntryCount, filtered, service)...)

}
func (a *adjTable) pduPerIP(change bool, ip uint32) []*pdu {
	pds := make([]*pdu, 0, 8)
	service := &serviceFields{
		ip:       ip,
		authType: sys.config.Neighbors[ip].KeyChain.AuthType,
	}

	filter := func(a *adj) bool { return a.nextHop != ip }
	filtered := a.filterBy(filter, change)
	return append(pds, limitPduSize(sys.config.Global.EntryCount, filtered, service)...)
}

func (a *adjTable) filterBy(filter filtFunc, change bool) []routeEntry {
	a.mux.RLock()
	defer a.mux.RUnlock()
	filtered := make([]routeEntry, 0, 4)

	for net, opt := range a.entries {
		if change {
			if change != opt.change {
				continue
			}
		}
		if filter(opt) {
			routeEntry := routeEntry{
				Network: net.IP,
				Mask:    net.Mask,
				Metric:  opt.metric,
				AFI:     afiIPv4,
			}
			filtered = append(filtered, routeEntry)
		}
	}
	return filtered
}

func limitPduSize(size int, entList []routeEntry, service *serviceFields) []*pdu {
	size -= authEntries[service.authType]
	count := (len(entList) / size) + 1
	pds := make([]*pdu, 8)

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

func (p *pdu) makeAuth(pass string) {
	switch p.serviceFields.authType {
	case authPlain:
		p.authKeyEntry = authKeyEntry{
			AFI:      afiAuth,
			AuthType: authPlain,
			Key:      padKey(pass),
		}
	case authHash:
		p.authHashEntry = authHashEntry{
			AFI:      afiAuth,
			AuthType: authHash,
			PackLng:  uint16(headerSize + entrySize + (len(p.routeEntries) * entrySize)),
			KeyID:    1,
			AuthLng:  uint8(entrySize),
			SQN:      uint32(time.Now().Unix()),
		}
		p.authKeyEntry = authKeyEntry{
			AFI:      afiAuth,
			AuthType: authKey,
			Key:      padKey(pass),
		}
	}
}
