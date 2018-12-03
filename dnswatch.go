package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	//"github.com/davecgh/go-spew/spew"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// yum install libpcap-1.4.0

func device() (ret []string) {
	fmt.Println("----------Find all devices---------\n ")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	// Print device information
	for _, device := range devices {
		if len(device.Addresses) < 1 {
			continue
		}
		fmt.Println(device.Name)
		for _, address := range device.Addresses {
			if len(address.IP) != 4 {
				continue
			}
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
			if fmt.Sprint(address.IP) != "127.0.0.1" {
				ret = append(ret, device.Name)
			}
		}
	}
	return
}

func main() {
	var deviceInterface string
	flag.StringVar(&deviceInterface, "interface", "eth0", "device interface to listen for DNS packets")
	flag.Parse()

	ret := device()
	if len(ret) > 0 {
		fmt.Println(ret)
		deviceInterface = ret[0]
	}

	handle, err := pcap.OpenLive(deviceInterface, 65535, true, 1000)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("port 53")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Watching for DNS packets on %s...\n", deviceInterface)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()
	for {
		select {
		case packet := <-packetChan:
			handlePacket(packet)
		}
	}
}

func handlePacket(packet gopacket.Packet) {
	metadata := packet.Metadata()
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	//arpLayer := packet.Layer(layers.LayerTypeARP)
	dns, _ := dnsLayer.(*layers.DNS)
	if len(dns.Answers) == 0 {
		return
	}
	for _, question := range dns.Questions {
		if question.Type == layers.DNSTypeA || question.Type == layers.DNSTypeAAAA {
			fmt.Printf("%s - %s [%d]\n", metadata.Timestamp.Format(time.ANSIC), string(question.Name), dns.ID)
		}
	}
	for _, answer := range dns.Answers {
		if answer.Type == layers.DNSTypeA {
			fmt.Printf("\t\t\t    -> A    %s\n", answer.String())
		} else if answer.Type == layers.DNSTypeAAAA {
			fmt.Printf("\t\t\t    -> AAAA %s\n", answer.String())
		}
	}
}
