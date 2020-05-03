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
var FLOW_RESP = []byte("\x01")
var FLOW_ORIG = []byte("\x02")

func simplify(r *pcapgo.Reader, w io.Writer) (int, error) {
	totalPackets := 0
	ps := gopacket.NewPacketSource(r, r.LinkType())
	for packet := range ps.Packets() {
		totalPackets++
		if nl := packet.NetworkLayer(); nl != nil {
			payload := nl.LayerContents()
			w.Write(MAGIC)
			w.Write(FLOW_ORIG)
			w.Write(payload)
		}
	}
	return totalPackets, nil

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

	outf, err := os.Create(output)
	if err != nil {
		log.Fatalf("Can't open output: %v", err)
		return
	}
	defer outf.Close()
	packets, err := simplify(r, outf)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d packets rewritten\n", packets)
}
