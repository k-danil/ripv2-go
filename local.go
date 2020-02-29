package main

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/vishvananda/netlink"
)

func getLocalTable(ifc string) (*pdu, error) {
	link, err := netlink.LinkByName(ifc)
	if err != nil {
		return nil, err
	}

	iplist, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	// TODO Check interface state
	pdu := &pdu{
		header: header{
			version: 2,
			command: 2,
		},
		serviceFields: serviceFields{
			ip:  binary.BigEndian.Uint32([]byte{127, 0, 0, 1}),
			ifn: link.Attrs().Name,
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

	return pdu, nil
}

func addLocalRoute(network, mask, nextHop uint32) error {
	if uintToIP(nextHop).Equal([]byte{127, 0, 0, 1}) {
		return nil
	}

	dst := &net.IPNet{
		IP:   uintToIP(network),
		Mask: net.IPMask(uintToIP(mask)),
	}
	route := netlink.Route{
		Dst:      dst,
		Protocol: 10,
		Priority: 31,
		Gw:       uintToIP(nextHop),
	}
	if err := netlink.RouteAdd(&route); err != nil {
		return err
	}
	return nil
}

func replaceLocalRoute(network, mask, nextHop uint32) error {
	if uintToIP(nextHop).Equal([]byte{127, 0, 0, 1}) {
		return nil
	}
	if err := removeLocalRoute(network, mask); err != nil {
		return err
	}
	if err := addLocalRoute(network, mask, nextHop); err != nil {
		return err
	}
	return nil
}

func removeLocalRoute(network, mask uint32) error {
	dst := &net.IPNet{
		IP:   uintToIP(network),
		Mask: net.IPMask(uintToIP(mask)),
	}
	route := netlink.Route{
		Dst:      dst,
		Protocol: 10,
		Priority: 31,
	}

	if err := netlink.RouteDel(&route); err != nil {
		return err
	}
	return nil
}

func clearLocalTable() {
	filter := &netlink.Route{
		Protocol: 10,
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, filter, netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		log.Println(err)
	}

	for _, route := range routes {
		if err := netlink.RouteDel(&route); err != nil {
			log.Println(route, err)
		}
	}
}

func isLocalAddress(addr net.IP) (bool, error) {
	iplist, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return false, err
	}

	for _, ip := range iplist {
		if ip.IP.Equal(addr) {
			return true, nil
		}
	}

	return false, nil
}
