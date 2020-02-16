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

type adj struct {
	ip      uint32
	mask    uint32
	nextHop uint32
	ifi     uint16
	metric  uint32
	timeout int64
	kill    bool
	change  bool
}

type adjTable struct {
	entry map[uint32]*adj
}

func initTable() *adjTable {
	a := &adjTable{}
	a.entry = make(map[uint32]*adj)
	go a.scheduler()
	return a
}

func (a *adjTable) scheduler() {
	for {
		a.clearAdj()
		time.Sleep(500 * time.Millisecond)
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
		switch timer := ctime - val.timeout; {
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
	for _, entry := range p.routeEntries {
		if a.entry[entry.network] == nil {
			entry.metric = infMetric
		} else {
			entry.metric = a.entry[entry.network].metric
		}
	}
	log.Println("TODO Trigger response")
}

func (a *adjTable) processResponse(p *pdu) {
	ctime := time.Now().Unix()
	for _, pEnt := range p.routeEntries {
		if a.entry[pEnt.network] == nil {
			if pEnt.metric != infMetric {
				a.entry[pEnt.network] = &adj{
					ip:      pEnt.network,
					mask:    pEnt.mask,
					nextHop: p.serviceFields.srcIP,
					ifi:     p.serviceFields.srcIf,
					metric:  pEnt.metric,
					timeout: ctime,
					change:  true,
				}
			}
		} else {
			if a.entry[pEnt.network].nextHop == p.serviceFields.srcIP {
				switch metric := pEnt.metric; {
				case metric == infMetric:
					if a.entry[pEnt.network].metric != infMetric {
						a.entry[pEnt.network].metric = metric
						a.entry[pEnt.network].change = true
						a.entry[pEnt.network].kill = true
					}
				case metric < a.entry[pEnt.network].metric:
					a.entry[pEnt.network].timeout = ctime
					a.entry[pEnt.network].metric = metric
					a.entry[pEnt.network].change = true
					a.entry[pEnt.network].kill = false
				case metric > a.entry[pEnt.network].metric:
				case metric == a.entry[pEnt.network].metric:
					a.entry[pEnt.network].timeout = ctime
				}
			} else {
				switch metric := pEnt.metric; {
				case metric == a.entry[pEnt.network].metric:
					if a.entry[pEnt.network].kill == true {
						a.entry[pEnt.network].nextHop = p.serviceFields.srcIP
						a.entry[pEnt.network].ifi = p.serviceFields.srcIf
						a.entry[pEnt.network].timeout = ctime
						a.entry[pEnt.network].metric = metric
						a.entry[pEnt.network].change = true
						a.entry[pEnt.network].kill = false
					}
				case metric < a.entry[pEnt.network].metric:
					a.entry[pEnt.network].nextHop = p.serviceFields.srcIP
					a.entry[pEnt.network].ifi = p.serviceFields.srcIf
					a.entry[pEnt.network].timeout = ctime
					a.entry[pEnt.network].metric = metric
					a.entry[pEnt.network].change = true
					a.entry[pEnt.network].kill = false
				}
			}
		}
	}
}
