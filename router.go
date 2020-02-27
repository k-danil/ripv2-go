package main

import (
	"fmt"
	"log"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	request  uint8 = 1
	response uint8 = 2
)

const (
	infMetric uint32 = 16
)

const (
	regular uint8 = 1
	changed uint8 = 2
)

type adjTable struct {
	entry   map[uint64]*adj
	mux     sync.Mutex
	connect *ipv4.PacketConn //Ugly shit
	change  bool
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
		"{ip:%v mask:%v nextHop:%v ifi:%v metric:%v timestamp:%v kill:%v change:%v}",
		uintToIP(a.ip), uintToIP(a.mask), uintToIP(a.nextHop), a.ifn, a.metric, a.timestamp, a.kill, a.change,
	)
}

func initTable(c *config) *adjTable {
	a := &adjTable{}
	a.entry = make(map[uint64]*adj)
	go a.scheduler(c)

	return a
}

func (a *adjTable) scheduler(c *config) {
	tWorker := time.NewTicker(5 * time.Second)
	tKeepAlive := time.NewTicker(time.Duration(c.Timers.UpdateTimer) * time.Second)
	for {
		select {
		case <-tKeepAlive.C:
			//TODO Move to subscriptions
			for i := range c.Interfaces {
				l, err := getLocalTable(i)
				if err != nil {
					log.Println(err)
				} else {
					a.adjProcess(l)
				}
			}

			go a.pduPerIf(regular, c)

		case <-tWorker.C:
			if a.change {
				go a.pduPerIf(changed, c)
			}
			a.adjClear(c)
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

func (a *adjTable) adjClear(c *config) {
	a.mux.Lock()
	defer a.mux.Unlock()
	ctime := time.Now().Unix()
	for key, val := range a.entry {
		switch timer := ctime - val.timestamp; {
		case timer > (c.Timers.GarbageTimer + c.Timers.TimeoutTimer):
			if val.kill {
				delete(a.entry, key)
			}
		case timer > c.Timers.TimeoutTimer:
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
	a.mux.Lock()
	defer a.mux.Unlock()
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
	// p.pduToPacket()
}

func (a *adjTable) responseProcess(p *pdu) {
	a.mux.Lock()
	defer a.mux.Unlock()
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
					ifn:       p.serviceFields.srcIf,
					metric:    pEnt.metric + 1,
					timestamp: ctime,
					change:    true,
				}
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
					a.entry[netid].timestamp = ctime
					a.entry[netid].metric = metric
					a.entry[netid].change = true
					a.entry[netid].kill = false
					a.change = true
				case metric == a.entry[netid].metric:
					a.entry[netid].timestamp = ctime
				}
			} else {
				switch metric := pEnt.metric + 1; {
				case metric == a.entry[netid].metric:
					if a.entry[netid].kill == true {
						a.entry[netid].nextHop = srcIP
						a.entry[netid].ifn = p.serviceFields.srcIf
						a.entry[netid].timestamp = ctime
						a.entry[netid].metric = metric + 1
						a.entry[netid].change = true
						a.entry[netid].kill = false
						a.change = true
					}
				case metric < a.entry[netid].metric:
					a.entry[netid].nextHop = srcIP
					a.entry[netid].ifn = p.serviceFields.srcIf
					a.entry[netid].timestamp = ctime
					a.entry[netid].metric = metric + 1
					a.entry[netid].change = true
					a.entry[netid].kill = false
					a.change = true
				}
			}
		}
	}
}

func (a *adjTable) pduPerIf(selector uint8, c *config) {
	for ifn, ifp := range c.Interfaces {
		if ifp.Passive {
			//Not send update to passive interface
			continue
		}

		//TODO Limit route entry per pdu

		p := a.adjToPdu(selector, ifn)
		if p != nil {
			// p.pduToPacket(c, ifn)
			sendToSocket(a.connect, p.pduToByte(c, ifn), ifn)
		}

		//Very bad idea. Place this in separate func
		if selector == changed {
			for _, adj := range a.entry {
				adj.change = false
			}
			a.change = false
		}
	}
}

func (a *adjTable) adjToPdu(selector uint8, ifn string) *pdu {
	a.mux.Lock()
	defer a.mux.Unlock()

	pdu := &pdu{
		header: header{command: 2, version: 2},
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
	}

	if len(pdu.routeEntries) > 0 {
		//Pointless to return zero sized pdu
		return pdu
	}
	return nil

}

func ipmask(ip, mask uint32) uint64 {
	im := (uint64(ip) << 32) | uint64(mask)

	return im
}
