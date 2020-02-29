package main

import (
	"log"
	"net"
)

type system struct {
	config *config
	socket *socket
}

func main() {
	clearLocalTable()
	// defer profile.Start(profile.TraceProfile).Stop()
	conf, err := readConfig()
	if err != nil {
		log.Fatal(err)
	}

	sys := &system{config: conf}

	//Listen for multicast on interfaces
	s, err := socketOpen(sys.config)
	if err != nil {
		log.Fatal(err)
	}

	sys.socket = s

	a := initTable(sys)

	sys.socket.joinMcast()
	defer sys.socket.close()
	defer clearLocalTable()

	//Receive packet in buffer
	for {
		b := make([]byte, 514) //Maximum size of RIP pdu - 504byte
		s, cm, _, err := sys.socket.connect.ReadFrom(b)
		if err != nil {
			log.Fatal(err)
		}
		ifc, err := net.InterfaceByIndex(cm.IfIndex)

		//Process received packet
		go func() {
			//Fill service fields and payload to struct
			packet, err := readPacket(b[:s], ifc.Name, cm.Src)
			if err != nil {
				//Drop weird sourced packet
				return
			}

			pdu := packet.parse()
			//Validate over RFC guidline and authenticate with pass
			err = pdu.validate(sys.config, packet.content)
			if err != nil {
				log.Println(err)
			} else {
				a.adjProcess(pdu)
			}
		}()
	}
}
