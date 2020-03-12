package main

import (
	"fmt"
	"sync"
	"time"
)

const (
	change bool = true
)

const (
	request  uint8 = 1
	response uint8 = 2
)

const (
	infMetric uint32 = 16
	invMetric uint32 = 255
)

type adjTable struct {
	entries map[ipNet]*adj
	mux     sync.Mutex
	change  bool
}

type ipNet struct {
	ip   uint32
	mask uint32
}

type adj struct {
	nextHop   uint32
	metric    uint32
	ifi       int
	timestamp int64
	kill      bool
	change    bool
}

func (a *adj) String() string {
	ctime := time.Now().Unix()
	return fmt.Sprintf(
		"nextHop:%v ifn:%v metric:%v uptime:%v kill:%v change:%v",
		uintToIP(a.nextHop), a.ifi, a.metric, ctime-a.timestamp, a.kill, a.change,
	)
}

func initAdjTable() *adjTable {
	a := &adjTable{}
	a.entries = make(map[ipNet]*adj)
	go a.scheduler()

	for i := range sys.config.Interfaces {
		l, err := getTable(i)
		if err != nil {
			sys.logger.send(erro, err)
		} else {
			a.procIncom(l)
		}
	}

	reqGiveAll()

	return a
}

func (a *adjTable) scheduler() {
	sys.logger.send(info, "starting scheduler")
	tWorker := time.NewTicker(5 * time.Second)
	tKeepAlive := time.NewTicker(time.Duration(sys.config.Timers.UpdateTimer) * time.Second)
	for {
		select {
		case <-tKeepAlive.C:
			go a.respUpdate(!change)

			for i := range sys.config.Interfaces {
				l, err := getTable(i)
				if err != nil {
					sys.logger.send(erro, err)
				} else {
					a.procIncom(l)
				}
			}
		case <-tWorker.C:
			if a.change {
				go a.respUpdate(change)
			}

			a.clear(&sys.config.Timers)
		case <-sys.signal.getAdj:
			sys.logger.send(user, a.entries)
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

func (a *adjTable) procIncom(p *pdu) {
	switch p.header.Command {
	case request:
		a.reqProc(p)
	case response:
		a.respProc(p)
	}
}

func (a *adjTable) clear(t *timers) {
	a.mux.Lock()
	defer a.mux.Unlock()
	ctime := time.Now().Unix()
	for net, opt := range a.entries {
		switch timer := ctime - opt.timestamp; {
		case timer > (t.GarbageTimer + t.TimeoutTimer):
			if opt.kill {
				err := remRoute(net)
				if err != nil {
					sys.logger.send(erro, err)
				}
				delete(a.entries, net)
			}
		case timer > t.TimeoutTimer:
			if !opt.kill {
				opt.metric = infMetric
				opt.change = change
				opt.kill = true
				a.change = change
			}
		}
	}
}

func (a *adjTable) reqProc(p *pdu) {
	if p.routeEntries[0].Metric == infMetric && p.routeEntries[0].Network == 0 {
		a.respToGive(p)
	} else {
		a.respToReq(p)
	}
}

func (a *adjTable) respProc(p *pdu) {
	a.mux.Lock()
	defer a.mux.Unlock()

	for _, pEnt := range p.routeEntries {
		netid := ipNet{ip: pEnt.Network, mask: pEnt.Mask}
		//Default next-hop is 0.0.0.0 but it can be anything else
		var nh uint32
		if pEnt.NextHop != 0 {
			nh = pEnt.NextHop
		} else {
			nh = p.serviceFields.ip
		}

		metric := pEnt.Metric + 1

		newAdj := func() *adj {
			return &adj{
				nextHop:   nh,
				ifi:       p.serviceFields.ifi,
				metric:    metric,
				timestamp: p.serviceFields.timestamp,
				change:    change,
			}
		}

		switch {
		case a.entries[netid] == nil:
			if metric < infMetric {
				a.entries[netid] = newAdj()
				a.change = change

				err := addRoute(netid, nh)
				if err != nil {
					sys.logger.send(erro, err)
				}
			}
		case a.entries[netid].nextHop == nh && metric == infMetric:
			if a.entries[netid].metric != infMetric {
				a.entries[netid].metric = metric
				a.entries[netid].change = change
				a.entries[netid].kill = true
				a.change = change
			}

		case a.entries[netid].nextHop == nh && metric < a.entries[netid].metric:
			a.entries[netid] = newAdj()
			a.change = change

		case a.entries[netid].nextHop == nh && metric == a.entries[netid].metric:
			a.entries[netid].timestamp = p.serviceFields.timestamp

		case a.entries[netid].kill == true && metric == a.entries[netid].metric:
			a.entries[netid] = newAdj()
			a.change = change

			err := replRoute(netid, nh)
			if err != nil {
				sys.logger.send(erro, err)
			}

		case metric < a.entries[netid].metric:
			a.entries[netid] = newAdj()
			a.change = change

			err := replRoute(netid, nh)
			if err != nil {
				sys.logger.send(erro, err)
			}
		}
	}
}

func (a *adjTable) clearChangeFlag() {
	a.mux.Lock()
	defer a.mux.Unlock()
	for _, opt := range a.entries {
		opt.change = !change
	}
	a.change = !change
}
