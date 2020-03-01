package main

import (
	"fmt"
	"log"
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
	system *system
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
		"ip:%v mask:%v nextHop:%v ifi:%v metric:%v timestamp:%v kill:%v change:%v",
		uintToIP(a.ip), uintToIP(a.mask), uintToIP(a.nextHop), a.ifn, a.metric, a.timestamp, a.kill, a.change,
	)
}

func initTable(sys *system) *adjTable {
	a := &adjTable{system: sys}
	a.entry = make(map[uint64]*adj)
	go a.scheduler()

	go a.pduPerIf(gettable)

	return a
}

func (a *adjTable) scheduler() {
	log.Println("Starting scheduler...")
	tWorker := time.NewTicker(5 * time.Second)
	tKeepAlive := time.NewTicker(time.Duration(a.system.config.Timers.UpdateTimer) * time.Second)
	for {
		select {
		case <-tKeepAlive.C:
			go a.pduPerIf(regular)

			//TODO Move to subscriptions
			for i := range a.system.config.Interfaces {
				l, err := getLocalTable(i)
				if err != nil {
					log.Println(err)
				} else {
					a.adjProcess(l)
				}
			}
		case <-tWorker.C:
			if a.change {
				go a.pduPerIf(changed)
			}

			a.clear()
		case <-a.system.signal.getAdj:
			for _, ent := range a.entry {
				log.Printf("%+v\n", ent)
			}
		case <-a.system.signal.stopSched:
			log.Println("Stoping scheduler...")
			return
		case <-a.system.signal.resetSched:
			log.Println("Stoping scheduler...")
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

func (a *adjTable) clear() {
	a.mux.Lock()
	defer a.mux.Unlock()
	ctime := time.Now().Unix()
	for key, val := range a.entry {
		switch timer := ctime - val.timestamp; {
		case timer > (a.system.config.Timers.GarbageTimer + a.system.config.Timers.TimeoutTimer):
			if val.kill {
				go removeLocalRoute(val.ip, val.mask)
				delete(a.entry, key)
			}
		case timer > a.system.config.Timers.TimeoutTimer:
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
			a.system.socket.sendMcast(pdu.pduToByte(a.system.config), pdu.serviceFields.ifn)
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
	a.system.socket.sendUcast(p.pduToByte(a.system.config), uintToIP(p.serviceFields.ip))
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

		if a.entry[netid] == nil {
			if (pEnt.metric + 1) < infMetric {
				a.entry[netid] = &adj{
					ip:        pEnt.network,
					mask:      pEnt.mask,
					nextHop:   srcIP,
					ifn:       p.serviceFields.ifn,
					metric:    pEnt.metric + 1,
					timestamp: p.serviceFields.timestamp,
					change:    true,
				}
				addLocalRoute(pEnt.network, pEnt.mask, srcIP)
				a.change = true
			}
		} else {
			if a.entry[netid].nextHop == srcIP {
				switch metric := pEnt.metric + 1; {
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
				switch metric := pEnt.metric + 1; {
				case metric == a.entry[netid].metric:
					if a.entry[netid].kill == true {
						a.entry[netid].nextHop = srcIP
						a.entry[netid].ifn = p.serviceFields.ifn
						a.entry[netid].timestamp = p.serviceFields.timestamp
						a.entry[netid].metric = metric + 1
						a.entry[netid].change = true
						a.entry[netid].kill = false

						replaceLocalRoute(pEnt.network, pEnt.mask, srcIP)
						a.change = true
					}
				case metric < a.entry[netid].metric:
					a.entry[netid].nextHop = srcIP
					a.entry[netid].ifn = p.serviceFields.ifn
					a.entry[netid].timestamp = p.serviceFields.timestamp
					a.entry[netid].metric = metric + 1
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
	for ifn, ifp := range a.system.config.Interfaces {
		if ifp.Passive {
			//Not send update to passive interface
			continue
		}

		pds := a.adjToPdu(selector, ifn)
		for _, pdu := range pds {
			a.system.socket.sendMcast(pdu.pduToByte(a.system.config), pdu.serviceFields.ifn)
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

	//TODO Limit route entry per pdu
	pds := make([]*pdu, 0)

	pdu := &pdu{
		header:        header{command: 2, version: 2},
		serviceFields: serviceFields{ifn: ifn},
	}

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
			pdu.routeEntries = append(pdu.routeEntries, routeEntry)
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
				pdu.routeEntries = append(pdu.routeEntries, routeEntry)
			}
		}
	case gettable:
		pdu.header.command = request
		pdu.routeEntries = []routeEntry{{metric: 16}}
	}

	if len(pdu.routeEntries) > 0 {
		//Pointless to return zero sized pdu
		pds := append(pds, pdu)
		return pds
	}
	return pds
}

func ipmask(ip, mask uint32) uint64 {
	im := (uint64(ip) << 32) | uint64(mask)

	return im
}
