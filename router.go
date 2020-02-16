package main

import (
	"log"
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
	tcleaner := time.NewTicker(1 * time.Second)
	tupdate := time.NewTicker(time.Duration(updateTimer) * time.Second)
	for {
		select {
		case <-tupdate.C:
			log.Println("TODO Out going update")
		case <-tcleaner.C:
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
	log.Printf("%+v", a)
	for _, val := range a.entry {
		log.Printf("%+v", val)
	}
}

func (a *adjTable) clearAdj() {
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
}

func (a *adjTable) processRequest(p *pdu) {
	if p.routeEntries[0].metric == infMetric && p.routeEntries[0].network == 0 {
		log.Println("TODO Trigger full table response")
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
}

func (a *adjTable) processResponse(p *pdu) {
	ctime := time.Now().Unix()
	for _, pEnt := range p.routeEntries {
		netid := ipmask(pEnt.network, pEnt.mask)
		if a.entry[netid] == nil {
			if pEnt.metric != infMetric {
				a.entry[netid] = &adj{
					ip:        pEnt.network,
					mask:      pEnt.mask,
					nextHop:   p.serviceFields.srcIP,
					ifi:       p.serviceFields.srcIf,
					metric:    pEnt.metric,
					timestamp: ctime,
					change:    true,
				}
			}
		} else {
			// TODO next hop from pdu
			if a.entry[netid].nextHop == p.serviceFields.srcIP {
				switch metric := pEnt.metric; {
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
				switch metric := pEnt.metric; {
				case metric == a.entry[netid].metric:
					if a.entry[netid].kill == true {
						a.entry[netid].nextHop = p.serviceFields.srcIP
						a.entry[netid].ifi = p.serviceFields.srcIf
						a.entry[netid].timestamp = ctime
						a.entry[netid].metric = metric
						a.entry[netid].change = true
						a.entry[netid].kill = false
					}
				case metric < a.entry[netid].metric:
					a.entry[netid].nextHop = p.serviceFields.srcIP
					a.entry[netid].ifi = p.serviceFields.srcIf
					a.entry[netid].timestamp = ctime
					a.entry[netid].metric = metric
					a.entry[netid].change = true
					a.entry[netid].kill = false
				}
			}
		}
	}
}

func ipmask(ip, mask uint32) uint64 {
	im := (uint64(ip) << 32) | uint64(mask)
	return im
}
