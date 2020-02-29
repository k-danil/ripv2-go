package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

type system struct {
	config *config
	socket *socket
}

func main() {
	sys := &system{}
	var err error

	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)
	// defer profile.Start(profile.TraceProfile).Stop()

	if sys.config, err = readConfig(); err != nil {
		log.Fatal(err)
	}

	if sys.socket, err = socketOpen(sys.config); err != nil {
		log.Fatal(err)
	}

	a := initTable(sys)

	go func() {
		<-term
		fmt.Println("\nClosing...")
		clearLocalTable()
		sys.socket.close()
		os.Exit(0)
	}()

	sys.socket.joinMcast()

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
