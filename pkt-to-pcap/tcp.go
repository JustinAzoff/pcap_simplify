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

type Endpoint struct {
	eth layers.Ethernet
	ip  layers.IPv4
	tcp layers.TCP
}

type TCPPacketGenerator struct {
	handle     *pcap.Handle
	SourceMAC  net.HardwareAddr
	DestMAC    net.HardwareAddr
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort layers.TCPPort
	DestPort   layers.TCPPort

	buf  gopacket.SerializeBuffer
	opts gopacket.SerializeOptions

	s_c Endpoint
	c_s Endpoint
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
		c_s: Endpoint{
			eth: layers.Ethernet{
				SrcMAC:       sourceMAC,
				DstMAC:       destMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			ip: layers.IPv4{
				SrcIP:    sourceIP,
				DstIP:    destIP,
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			},
		},
		s_c: Endpoint{
			eth: layers.Ethernet{
				SrcMAC:       destMAC,
				DstMAC:       sourceMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			ip: layers.IPv4{
				SrcIP:    destIP,
				DstIP:    sourceIP,
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			},
		},
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
	t.s_c.tcp = layers.TCP{
		SrcPort: t.SourcePort,
		DstPort: t.DestPort,
	}
	t.c_s.tcp = layers.TCP{
		SrcPort: t.DestPort,
		DstPort: t.SourcePort,
	}
	// SYN
	t.c_s.tcp.SYN = true
	t.c_s.tcp.Ack++
	t.c_s.tcp.SetNetworkLayerForChecksum(&t.c_s.ip)
	if err := t.send(&t.c_s.eth, &t.c_s.ip, &t.c_s.tcp); err != nil {
		log.Fatal(err)
	}

	//synack
	t.s_c.tcp.SYN = true
	t.s_c.tcp.ACK = true
	t.s_c.tcp.Seq++
	t.s_c.tcp.Ack++
	t.s_c.tcp.SetNetworkLayerForChecksum(&t.s_c.ip)
	t.s_c.tcp.Window = 32000

	if err := t.send(&t.s_c.eth, &t.s_c.ip, &t.s_c.tcp); err != nil {
		log.Fatal(err)
	}
	//ack
	t.c_s.tcp.ACK = true
	t.c_s.tcp.SYN = false
	t.c_s.tcp.Seq++
	t.c_s.tcp.Ack++
	t.c_s.tcp.Window = 32000
	t.c_s.tcp.SetNetworkLayerForChecksum(&t.c_s.ip)
	if err := t.send(&t.c_s.eth, &t.c_s.ip, &t.c_s.tcp); err != nil {
		log.Fatal(err)
	}
	t.c_s.tcp.SYN = false
	t.s_c.tcp.SYN = false
}

func (t *TCPPacketGenerator) Write(data []byte, isOrig bool, autoAck bool) error {
	//Client or server endpoints, depending on isOrig
	var a, b Endpoint
	if isOrig {
		a = t.c_s
		b = t.s_c
	} else {
		a = t.s_c
		b = t.s_c
	}
	a.tcp.ACK = true
	a.tcp.PSH = true
	payload := gopacket.Payload(data)
	if err := t.send(&a.eth, &a.ip, &a.tcp, &payload); err != nil {
		log.Fatal(err)
	}
	a.tcp.Seq += uint32(len(payload))
	b.tcp.Ack += uint32(len(payload))

	if autoAck {
		b.tcp.ACK = true
		if err := t.send(&b.eth, &b.ip, &b.tcp); err != nil {
			log.Fatal(err)
		}
	}

	return nil
}
func (t *TCPPacketGenerator) Close() {
	//send fin
	t.c_s.tcp.FIN = true
	if err := t.send(&t.c_s.eth, &t.c_s.ip, &t.c_s.tcp); err != nil {
		log.Fatal(err)
	}

	//ack clients fin, then send our own
	t.s_c.tcp.ACK = true
	t.s_c.tcp.PSH = false
	if err := t.send(&t.s_c.eth, &t.s_c.ip, &t.s_c.tcp); err != nil {
		log.Fatal(err)
	}
	t.s_c.tcp.FIN = true
	t.s_c.tcp.ACK = true
	if err := t.send(&t.s_c.eth, &t.s_c.ip, &t.s_c.tcp); err != nil {
		log.Fatal(err)
	}
	//client ack clients fin
	t.c_s.tcp.FIN = false
	t.c_s.tcp.ACK = true
	t.c_s.tcp.Ack++
	t.c_s.tcp.Seq++
	if err := t.send(&t.c_s.eth, &t.c_s.ip, &t.c_s.tcp); err != nil {
		log.Fatal(err)
	}
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
	t.Connect(0, 80)
	connect := []byte("CONNECT foo HTTP/1.1\r\n\r\n")
	reply := []byte("HTTP/1.1 200 OK\r\n\r\n")
	t.Write(connect, true, false)
	t.Write(reply, false, false)
	t.Close()
	/*
		connect := gopacket.Payload([]byte("CONNECT foo HTTP/1.1\r\n\r\n"))

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
