package main

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshotLen uint32 = 1500
)

type TCPPacketGenerator struct {
	handle     *pcap.Handle
	SourceMAC  net.HardwareAddr
	DestMAC    net.HardwareAddr
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort layers.TCPPort
	DestPort   layers.TCPPort
	buf        gopacket.SerializeBuffer
	opts       gopacket.SerializeOptions
}

func NewTCPPacketGenerator(handle *pcap.Handle) (*TCPPacketGenerator, error) {
	//TODO: move to params or whatever
	smac := "00:00:00:00:00:01"
	dmac := "00:00:00:00:00:02"
	sip := "10.0.0.1"
	dip := "10.0.0.2"

	sourceMAC, err := net.ParseMAC(smac)
	if err != nil {
		return nil, fmt.Errorf("Invalid mac: %v: %w", smac)
	}

	destMAC, err := net.ParseMAC(dmac)
	if err != nil {
		return nil, fmt.Errorf("Invalid mac: %v: %w", dmac)
	}
	sourceIP := net.ParseIP(sip)
	if sourceIP == nil {
		return nil, fmt.Errorf("Invalid ip: %v", sip)
	}
	destIP := net.ParseIP(dip)
	if destIP == nil {
		return nil, fmt.Errorf("Invalid ip: %v", dip)
	}
	t := TCPPacketGenerator{
		opts: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
		buf:       gopacket.NewSerializeBuffer(),
		handle:    handle,
		SourceMAC: sourceMAC,
		DestMAC:   destMAC,
		SourceIP:  sourceIP,
		DestIP:    destIP,
	}
	return &t, nil
}

func (t *TCPPacketGenerator) Connect(sourcePort, destPort int) {
	if sourcePort == 0 {
		s1 := rand.NewSource(time.Now().UnixNano())
		r1 := rand.New(s1)
		sourcePort = 32000 + r1.Intn(32000)
	}

	t.SourcePort = layers.TCPPort(sourcePort)
	t.DestPort = layers.TCPPort(destPort)
	log.Printf("Generating initial connection from %d to %d", sourcePort, destPort)
	c_s_eth := layers.Ethernet{
		SrcMAC:       t.SourceMAC,
		DstMAC:       t.DestMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	s_c_eth := layers.Ethernet{
		SrcMAC:       t.DestMAC,
		DstMAC:       t.SourceMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	c_s_ip4 := layers.IPv4{
		SrcIP:    t.SourceIP,
		DstIP:    t.DestIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	s_c_ip4 := layers.IPv4{
		SrcIP:    t.DestIP,
		DstIP:    t.SourceIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	c_s_tcp := layers.TCP{
		SrcPort: t.SourcePort,
		DstPort: t.DestPort,
	}
	s_c_tcp := layers.TCP{
		SrcPort: t.DestPort,
		DstPort: t.SourcePort,
	}
	// SYN
	c_s_tcp.SYN = true
	c_s_tcp.Ack++
	c_s_tcp.SetNetworkLayerForChecksum(&c_s_ip4)
	if err := t.send(&c_s_eth, &c_s_ip4, &c_s_tcp); err != nil {
		log.Fatal(err)
	}

	//synack
	s_c_tcp.SYN = true
	s_c_tcp.ACK = true
	s_c_tcp.Seq++
	s_c_tcp.Ack++
	s_c_tcp.SetNetworkLayerForChecksum(&s_c_ip4)
	s_c_tcp.Window = 32000

	if err := t.send(&s_c_eth, &s_c_ip4, &s_c_tcp); err != nil {
		log.Fatal(err)
	}
	//ack
	c_s_tcp.ACK = true
	c_s_tcp.SYN = false
	c_s_tcp.Seq++
	c_s_tcp.Ack++
	c_s_tcp.Window = 32000
	c_s_tcp.SetNetworkLayerForChecksum(&c_s_ip4)
	if err := t.send(&c_s_eth, &c_s_ip4, &c_s_tcp); err != nil {
		log.Fatal(err)
	}

	//clear flags
	c_s_tcp.SYN = false
	s_c_tcp.SYN = false
}

func (t *TCPPacketGenerator) send(l ...gopacket.SerializableLayer) error {
	if err := gopacket.SerializeLayers(t.buf, t.opts, l...); err != nil {
		return err
	}
	return t.handle.WritePacketData(t.buf.Bytes())
}

func main() {
	handle, err := pcap.OpenLive("en7", 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	t, err := NewTCPPacketGenerator(handle)
	if err != nil {
		log.Fatalf("Failed: %w", err)
	}
	t.Connect(0, 445)

	/*
		connect := gopacket.Payload([]byte("CONNECT foo HTTP/1.1\r\n\r\n"))
		reply := gopacket.Payload([]byte("HTTP/1.1 200 OK\r\n\r\n"))

		eth := layers.Ethernet{
			SrcMAC:       sMac,
			DstMAC:       dMac,
			EthernetType: layers.EthernetTypeIPv4,
		}
		c_s_ip4 := layers.IPv4{
			SrcIP:    sIP,
			DstIP:    dIP,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		s_c_ip4 := layers.IPv4{
			SrcIP:    dIP,
			DstIP:    sIP,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
		}
		c_s_tcp := layers.TCP{
			SrcPort: layers.TCPPort(sPort),
			DstPort: 8000,
		}
		s_c_tcp := layers.TCP{
			SrcPort: 8000,
			DstPort: layers.TCPPort(sPort),
		}
		// SYN
		c_s_tcp.SYN = true
		c_s_tcp.Ack++
		c_s_tcp.SetNetworkLayerForChecksum(&c_s_ip4)
		if err := s.send(&eth, &c_s_ip4, &c_s_tcp); err != nil {
			log.Fatal(err)
		}

		//synack
		s_c_tcp.SYN = true
		s_c_tcp.ACK = true
		s_c_tcp.Seq++
		s_c_tcp.Ack++
		s_c_tcp.SetNetworkLayerForChecksum(&s_c_ip4)
		s_c_tcp.Window = 32000

		if err := s.send(&eth, &s_c_ip4, &s_c_tcp); err != nil {
			log.Fatal(err)
		}
		//ack
		c_s_tcp.ACK = true
		c_s_tcp.SYN = false
		c_s_tcp.Seq++
		c_s_tcp.Ack++
		c_s_tcp.Window = 32000
		c_s_tcp.SetNetworkLayerForChecksum(&c_s_ip4)
		if err := s.send(&eth, &c_s_ip4, &c_s_tcp); err != nil {
			log.Fatal(err)
		}

		//clear flags
		c_s_tcp.SYN = false
		s_c_tcp.SYN = false

		//CONNECT
		c_s_tcp.ACK = true
		c_s_tcp.PSH = true
		if err := s.send(&eth, &c_s_ip4, &c_s_tcp, &connect); err != nil {
			log.Fatal(err)
		}
		c_s_tcp.Seq += uint32(len(connect))
		s_c_tcp.Ack += uint32(len(connect))

		//reply
		s_c_tcp.Seq++
		if err := s.send(&eth, &s_c_ip4, &s_c_tcp, &reply); err != nil {
			log.Fatal(err)
		}
		s_c_tcp.Seq += uint32(len(reply))
		c_s_tcp.Ack += 1 + uint32(len(reply))

		//send fin
		s_c_tcp.FIN = true
		if err := s.send(&eth, &s_c_ip4, &s_c_tcp); err != nil {
			log.Fatal(err)
		}

		//ack servers fin, then send our own
		c_s_tcp.ACK = true
		c_s_tcp.PSH = false
		if err := s.send(&eth, &c_s_ip4, &c_s_tcp); err != nil {
			log.Fatal(err)
		}
		c_s_tcp.FIN = true
		c_s_tcp.ACK = true
		if err := s.send(&eth, &c_s_ip4, &c_s_tcp); err != nil {
			log.Fatal(err)
		}
		//server ack clients fin
		s_c_tcp.FIN = false
		s_c_tcp.ACK = true
		s_c_tcp.Ack++
		s_c_tcp.Seq++
		if err := s.send(&eth, &s_c_ip4, &s_c_tcp); err != nil {
			log.Fatal(err)
		}
	*/
}
