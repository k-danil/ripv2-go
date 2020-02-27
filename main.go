package main

import (
	"log"
	"net"
)

func main() {
	// defer profile.Start(profile.TraceProfile).Stop()
	conf, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	a := initTable(conf)

	//Listen for multicast on interfaces
	p, err := socketOpen(conf)
	if err != nil {
		log.Fatal(err)
	}
	a.connect = p
	defer socketClose(p, conf)

	//Receive packet in buffer
	for {
		b := make([]byte, 514) //Maximum size of RIP pdu - 504byte
		s, cm, _, err := p.ReadFrom(b)
		if err != nil {
			log.Fatal(err)
		}
		ifc, err := net.InterfaceByIndex(cm.IfIndex)
		//Process received packet
		go func() {
			//Fill service fields and payload to struct
			r, err := readPacket(b[:s], ifc.Name, cm.Src)
			if err != nil {
				log.Fatal(err)
			}
			//Validate over RFC guidline and authenticate with pass
			m, err := r.pduValidator(conf)
			if err != nil {
				log.Println(err)
			} else {
				a.adjProcess(m)
			}
		}()
	}
}
