package main

import (
	"log"
	"sync"
	"time"
)

const (
	updateTimer  int64 = 30
	timeoutTimer int64 = 180
	garbageTimer int64 = 120
)

const (
	request  uint8 = 1
	response uint8 = 2
)

const (
	infMetric uint32 = 16
)

type adjTable struct {
	entry map[uint64]*adj
	mux   sync.Mutex
}

type adj struct {
	ip        uint32
	mask      uint32
	nextHop   uint32
	ifi       uint16
	metric    uint32
	timestamp int64
	kill      bool
	change    bool
}

func initTable() *adjTable {
	a := &adjTable{}
	a.entry = make(map[uint64]*adj)
	go a.scheduler()
	return a
}

func (a *adjTable) scheduler() {
	tWorker := time.NewTicker(1 * time.Second)
	tKeepAlive := time.NewTicker(time.Duration(updateTimer) * time.Second)
	for {
		select {
		case <-tKeepAlive.C:
			a.pduProcessor(getLocalTable())
			log.Println("TODO Out going update")
			log.Printf("%+v", a)
			for _, val := range a.entry {
				log.Printf("%+v", val)
			}
		case <-tWorker.C:
			a.clearAdj()
		}
	}
}

func (a *adjTable) pduProcessor(p *pdu) {
	switch p.header.command {
	case request:
		a.processRequest(p)
	case response:
		a.processResponse(p)
	}
}

func (a *adjTable) clearAdj() {
	a.mux.Lock()
	ctime := time.Now().Unix()
	for key, val := range a.entry {
		switch timer := ctime - val.timestamp; {
		case timer > (garbageTimer + timeoutTimer):
			if val.kill {
				delete(a.entry, key)
			}
		case timer > timeoutTimer:
			if !val.kill {
				val.metric = infMetric
				val.change = true
				val.kill = true
			}
		}
	}
	a.mux.Unlock()
}

func (a *adjTable) processRequest(p *pdu) {
	a.mux.Lock()
	if p.routeEntries[0].metric == infMetric && p.routeEntries[0].network == 0 {
		log.Println("TODO Trigger full table response")
		a.mux.Unlock()
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
	log.Println("TODO Trigger response")
	a.mux.Unlock()
}

func (a *adjTable) processResponse(p *pdu) {
	a.mux.Lock()
	ctime := time.Now().Unix()
	for _, pEnt := range p.routeEntries {
		//Calculate id to map
		netid := ipmask(pEnt.network, pEnt.mask)
		//Default next-hop is 0.0.0.0 but it can be anything else
		var srcIP uint32
		if pEnt.nextHop != 0 {
			srcIP = pEnt.nextHop
		} else {
			srcIP = p.serviceFields.srcIP
		}

		if a.entry[netid] == nil {
			if (pEnt.metric + 1) < infMetric {
				a.entry[netid] = &adj{
					ip:        pEnt.network,
					mask:      pEnt.mask,
					nextHop:   srcIP,
					ifi:       p.serviceFields.srcIf,
					metric:    pEnt.metric + 1,
					timestamp: ctime,
					change:    true,
				}
			}
		} else {
			if a.entry[netid].nextHop == srcIP {
				switch metric := pEnt.metric + 1; {
				case metric == infMetric:
					if a.entry[netid].metric != infMetric {
						a.entry[netid].metric = metric
						a.entry[netid].change = true
						a.entry[netid].kill = true
					}
				case metric < a.entry[netid].metric:
					a.entry[netid].timestamp = ctime
					a.entry[netid].metric = metric
					a.entry[netid].change = true
					a.entry[netid].kill = false
				case metric == a.entry[netid].metric:
					a.entry[netid].timestamp = ctime
				}
			} else {
				switch metric := pEnt.metric + 1; {
				case metric == a.entry[netid].metric:
					if a.entry[netid].kill == true {
						a.entry[netid].nextHop = srcIP
						a.entry[netid].ifi = p.serviceFields.srcIf
						a.entry[netid].timestamp = ctime
						a.entry[netid].metric = metric
						a.entry[netid].change = true
						a.entry[netid].kill = false
					}
				case metric < a.entry[netid].metric:
					a.entry[netid].nextHop = srcIP
					a.entry[netid].ifi = p.serviceFields.srcIf
					a.entry[netid].timestamp = ctime
					a.entry[netid].metric = metric
					a.entry[netid].change = true
					a.entry[netid].kill = false
				}
			}
		}
	}
	a.mux.Unlock()
}

// func (a *adjTable) outgoingAdj(changed bool) *pdu {
// 	pdu := &pdu{
// 		header: header{command: 2, version: 2},
// 	}
// 	for aEnt := range a.entry {
// 		switch changed {
// 		case true:

// 		case false:
// 		}
// 	}
// 	return pdu
// }

func ipmask(ip, mask uint32) uint64 {
	im := (uint64(ip) << 32) | uint64(mask)
	return im
}
