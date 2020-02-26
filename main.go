package main

import (
	"log"
	"net"
)

func main() {
	conf, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	a := initTable()

	//Listen for multicast on interfaces
	p := socket(conf)
	defer socketClose(p, conf)

	//Receive packet in buffer
	for {
		b := make([]byte, 514) //Maximum size of RIP pdu - 504byte
		s, cm, _, err := p.ReadFrom(b)
		if err != nil {
			log.Fatal(err)
		} else if s != 0 {
			//Process received packet
			go func() {
				//Fill service fields and payload to struct
				ifi, _ := net.InterfaceByIndex(cm.IfIndex)
				r, err := read(b[:s], cm.IfIndex, cm.Src, ifi.Name)
				if err != nil {
					log.Fatal(err)
				}
				//Parse payload
				r.parser()
				// log.Printf("%+v", r)
				//Validate over RFC guidline and authenticate with pass
				m, err := r.validator(conf)
				// log.Printf("%+v", m)
				if err != nil {
					log.Println(err)
				} else {
					a.pduProcessor(m)
				}
			}()
		}
	}
}
