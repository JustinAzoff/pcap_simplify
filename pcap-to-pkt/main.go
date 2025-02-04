package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

var MAGIC = []byte("\x01PKT")
var FLOW_ORIG = []byte("\x01")
var FLOW_RESP = []byte("\x02")

func simplify(r *pcapgo.Reader, w io.Writer) (int, int, error) {

	totalPackets := 0
	packetsWritten := 0
	ps := gopacket.NewPacketSource(r, r.LinkType())
	firstSeenFlow := ""
	for packet := range ps.Packets() {
		totalPackets++
		flow := fmt.Sprintf("%v %v", packet.NetworkLayer().NetworkFlow(), packet.TransportLayer().TransportFlow())
		if firstSeenFlow == "" {
			firstSeenFlow = flow
		}
		//fmt.Printf("First=%s, this=%s\n", firstSeenFlow, flow)
		if tl := packet.TransportLayer(); tl != nil {
			packetsWritten++
			payload := tl.LayerPayload()
			w.Write(MAGIC)
			if flow == firstSeenFlow {
				w.Write(FLOW_ORIG)
			} else {
				w.Write(FLOW_RESP)
			}
			w.Write(payload)
		}
	}
	return totalPackets, packetsWritten, nil

}

func main() {
	flag.Parse()

	if len(flag.Args()) != 2 {
		fmt.Printf("Usage: %s infile outfile\n", os.Args[0])
		os.Exit(1)
	}

	input := flag.Args()[0]
	output := flag.Args()[1]

	inf, err := os.Open(input)
	if err != nil {
		log.Fatalf("Can't open input: %v", err)
		return
	}
	defer inf.Close()

	r, err := pcapgo.NewReader(inf)
	if err != nil {
		log.Fatalf("Can't parse input as pcap file: %v", err)
		return
	}

	outf, err := os.Create(output)
	if err != nil {
		log.Fatalf("Can't open output: %v", err)
		return
	}
	defer outf.Close()
	totalPackets, packetsWritten, err := simplify(r, outf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d packets rewritten out of %d total packets\n", packetsWritten, totalPackets)
}
