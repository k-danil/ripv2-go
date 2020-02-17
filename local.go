package main

import (
	"encoding/binary"

	"github.com/vishvananda/netlink"
)

func getLocalTable() *pdu {
	link, _ := netlink.LinkByName("lo")
	iplist, _ := netlink.AddrList(link, netlink.FAMILY_V4)
	pdu := &pdu{
		header: header{
			version: 2,
			command: 2,
		},
		serviceFields: serviceFields{
			srcIP: binary.BigEndian.Uint32([]byte{127, 0, 0, 1}),
			srcIf: uint16(link.Attrs().Index),
		},
	}
	for i := 0; i < len(iplist); i++ {
		if iplist[i].IP.IsLoopback() {
			continue
		}
		routeEntry := routeEntry{
			afi:     afiIPv4,
			network: binary.BigEndian.Uint32(iplist[i].IP.Mask(iplist[i].Mask)),
			mask:    binary.BigEndian.Uint32(iplist[i].Mask),
			metric:  0,
			nextHop: 0,
		}
		pdu.routeEntries = append(pdu.routeEntries, routeEntry)
	}
	return pdu
}
