package main

import "time"

type adj struct {
	ip      uint32
	mask    uint32
	gw      uint32
	ifi     uint16
	metric  uint32
	timeout int64
	change  bool
}

type adjTable struct {
	entry map[uint32]adj
}

func incomingProcessor(p *pdu) {

}

func initTable() *adjTable {
	a := &adjTable{}
	return a
}

func (a *adjTable) scheduler() {

}

func (a *adjTable) pduToAdj(p *pdu) {
	for _, entry := range p.routeEntries {
		if a.entry[entry.ip].ip == 0 {
			a.entry[entry.ip] = adj{
				ip:      entry.ip,
				mask:    entry.mask,
				gw:      p.serviceFields.srcIP,
				ifi:     p.serviceFields.srcIf,
				metric:  entry.metric,
				timeout: time.Now().Unix(),
				change:  true,
			}
		} else {
			if a.entry[entry.ip].ifi == p.serviceFields.srcIf {
				a.entry[entry.ip] = adj{
					metric:  entry.metric,
					timeout: time.Now().Unix(),
				}
			}
		}
	}
}
