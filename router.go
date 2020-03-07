package main

import (
	"fmt"
	"sync"
	"time"
)

const (
	request  uint8 = 1
	response uint8 = 2
)

const (
	infMetric uint32 = 16
	invMetric uint32 = 255
)

const (
	regular  uint8 = 1
	changed  uint8 = 2
	gettable uint8 = 3
)

type adjTable struct {
	entry  map[uint64]*adj
	mux    sync.Mutex
	change bool
}

type adj struct {
	ip        uint32
	mask      uint32
	nextHop   uint32
	ifn       string
	metric    uint32
	timestamp int64
	kill      bool
	change    bool
}

func (a *adj) String() string {
	return fmt.Sprintf(
		"ip:%v mask:%v nextHop:%v ifn:%v metric:%v timestamp:%v kill:%v change:%v",
		uintToIP(a.ip), uintToIP(a.mask), uintToIP(a.nextHop), a.ifn, a.metric, a.timestamp, a.kill, a.change,
	)
}

func initTable() *adjTable {
	a := &adjTable{}
	a.entry = make(map[uint64]*adj)
	go a.scheduler()

	go a.pduPerIf(gettable)

	return a
}

func (a *adjTable) scheduler() {
	sys.logger.send(info, "starting scheduler")
	tWorker := time.NewTicker(5 * time.Second)
	tKeepAlive := time.NewTicker(time.Duration(sys.config.Timers.UpdateTimer) * time.Second)
	for {
		select {
		case <-tKeepAlive.C:
			go a.pduPerIf(regular)

			for i := range sys.config.Interfaces {
				l, err := getLocalTable(i)
				if err != nil {
					sys.logger.send(erro, err)
				} else {
					a.adjProcess(l)
				}
			}
		case <-tWorker.C:
			if a.change {
				go a.pduPerIf(changed)
			}

			a.clear(&sys.config.Timers)
		case <-sys.signal.getAdj:
			sys.logger.send(user, a.entry)
		case <-sys.signal.stopSched:
			defer sys.logger.send(info, "stoping scheduler")
			return
		case <-sys.signal.resetSched:
			defer sys.logger.send(info, "stoping scheduler")
			go a.scheduler()
			return
		}
	}
}

func (a *adjTable) adjProcess(p *pdu) {
	switch p.header.command {
	case request:
		a.requestProcess(p)
	case response:
		a.responseProcess(p)
	}
}

func (a *adjTable) clear(t *timers) {
	a.mux.Lock()
	defer a.mux.Unlock()
	ctime := time.Now().Unix()
	for key, val := range a.entry {
		switch timer := ctime - val.timestamp; {
		case timer > (t.GarbageTimer + t.TimeoutTimer):
			if val.kill {
				go removeLocalRoute(val.ip, val.mask)
				delete(a.entry, key)
			}
		case timer > t.TimeoutTimer:
			if !val.kill {
				val.metric = infMetric
				val.change = true
				val.kill = true
				a.change = true
			}
		}
	}
}

func (a *adjTable) requestProcess(p *pdu) {
	if p.routeEntries[0].metric == infMetric && p.routeEntries[0].network == 0 {
		pds := a.adjToPdu(regular, p.serviceFields.ifn)
		for _, pdu := range pds {
			sys.socket.sendMcast(pdu.pduToByte(), pdu.serviceFields.ifn)
		}
		return
	}
	for _, pEnt := range p.routeEntries {
		netid := ipmask(pEnt.network, pEnt.mask)
		if a.entry[netid] == nil {
			pEnt.metric = infMetric
		} else {
			pEnt.metric = a.entry[netid].metric
		}
	}
	sys.socket.sendUcast(p.pduToByte(), uintToIP(p.serviceFields.ip))
}

func (a *adjTable) responseProcess(p *pdu) {
	a.mux.Lock()
	defer a.mux.Unlock()

	for _, pEnt := range p.routeEntries {
		//Calculate id to map
		netid := ipmask(pEnt.network, pEnt.mask)
		//Default next-hop is 0.0.0.0 but it can be anything else
		var srcIP uint32
		if pEnt.nextHop != 0 {
			srcIP = pEnt.nextHop
		} else {
			srcIP = p.serviceFields.ip
		}

		metric := pEnt.metric + 1

		if a.entry[netid] == nil {
			if metric < infMetric {
				a.entry[netid] = &adj{
					ip:        pEnt.network,
					mask:      pEnt.mask,
					nextHop:   srcIP,
					ifn:       p.serviceFields.ifn,
					metric:    metric,
					timestamp: p.serviceFields.timestamp,
					change:    true,
				}
				addLocalRoute(pEnt.network, pEnt.mask, srcIP)
				a.change = true
			}
		} else {
			if a.entry[netid].nextHop == srcIP {
				switch {
				case metric == infMetric:
					if a.entry[netid].metric != infMetric {
						a.entry[netid].metric = metric
						a.entry[netid].change = true
						a.entry[netid].kill = true
						a.change = true
					}
				case metric < a.entry[netid].metric:
					a.entry[netid].timestamp = p.serviceFields.timestamp
					a.entry[netid].metric = metric
					a.entry[netid].change = true
					a.entry[netid].kill = false
					a.change = true
				case metric == a.entry[netid].metric:
					a.entry[netid].timestamp = p.serviceFields.timestamp
				}
			} else {
				switch {
				case metric == a.entry[netid].metric:
					if a.entry[netid].kill == true {
						a.entry[netid].nextHop = srcIP
						a.entry[netid].ifn = p.serviceFields.ifn
						a.entry[netid].timestamp = p.serviceFields.timestamp
						a.entry[netid].metric = metric
						a.entry[netid].change = true
						a.entry[netid].kill = false

						replaceLocalRoute(pEnt.network, pEnt.mask, srcIP)
						a.change = true
					}
				case metric < a.entry[netid].metric:
					a.entry[netid].nextHop = srcIP
					a.entry[netid].ifn = p.serviceFields.ifn
					a.entry[netid].timestamp = p.serviceFields.timestamp
					a.entry[netid].metric = metric
					a.entry[netid].change = true
					a.entry[netid].kill = false

					replaceLocalRoute(pEnt.network, pEnt.mask, srcIP)
					a.change = true
				}
			}
		}
	}
}

func (a *adjTable) pduPerIf(selector uint8) {
	for ifn, ifp := range sys.config.Interfaces {
		if ifp.Passive {
			//Not send update to passive interface
			continue
		}

		pds := a.adjToPdu(selector, ifn)
		for _, pdu := range pds {
			sys.socket.sendMcast(pdu.pduToByte(), pdu.serviceFields.ifn)
		}

		if selector == changed {
			a.cleanChangeFlag()
		}
	}
}

func (a *adjTable) cleanChangeFlag() {
	a.mux.Lock()
	defer a.mux.Unlock()
	for _, adj := range a.entry {
		adj.change = false
	}
	a.change = false
}

func (a *adjTable) adjToPdu(selector uint8, ifn string) []*pdu {
	a.mux.Lock()
	defer a.mux.Unlock()

	pds := make([]*pdu, 0)
	entries := make([]routeEntry, 0)

	switch selector {
	case regular:
		for _, adj := range a.entry {
			if ifn == adj.ifn {
				//Split-horizon
				continue
			}
			routeEntry := routeEntry{
				network:  adj.ip,
				mask:     adj.mask,
				nextHop:  0,
				metric:   adj.metric,
				afi:      afiIPv4,
				routeTag: 0,
			}
			entries = append(entries, routeEntry)
		}
	case changed:
		for _, adj := range a.entry {
			if adj.change {
				if ifn == adj.ifn {
					//Split-horizon
					continue
				}
				routeEntry := routeEntry{
					network:  adj.ip,
					mask:     adj.mask,
					nextHop:  0,
					metric:   adj.metric,
					afi:      afiIPv4,
					routeTag: 0,
				}
				adj.change = false
				entries = append(entries, routeEntry)
			}
		}
	case gettable:
		pdu := &pdu{
			header:        header{command: request, version: 2},
			serviceFields: serviceFields{ifn: ifn},
		}
		pdu.routeEntries = []routeEntry{{metric: 16}}
		return append(pds, pdu)
	}

	var msgSize int

	switch sys.config.Interfaces[ifn].KeyChain.AuthType {
	case authHash:
		msgSize = sys.config.Local.MsgSize - 2
	case authPlain:
		msgSize = sys.config.Local.MsgSize - 1
	case authNon:
		msgSize = sys.config.Local.MsgSize
	}

	if len(entries) > 0 {
		pds = reLimit(msgSize, entries, ifn)
	}

	return pds
}

func reLimit(limit int, entries []routeEntry, ifn string) []*pdu {
	size := (len(entries) / limit) + 1
	pds := make([]*pdu, size)

	for i := 0; i < size; i++ {
		pds[i] = &pdu{
			header:        header{command: response, version: 2},
			serviceFields: serviceFields{ifn: ifn},
		}
	}

	for pos, entry := range entries {
		pds[pos/limit].routeEntries = append(pds[pos/limit].routeEntries, entry)
	}

	return pds
}

func ipmask(ip, mask uint32) uint64 {
	im := (uint64(ip) << 32) | uint64(mask)

	return im
}
