package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

var MAGIC = []byte("\x01PKT")
var FLOW_ORIG = byte('\x01')

type BufferSplitter struct {
	data []byte // Could this just be a type alias for []byte?
}

func NewBufferSplitter(data []byte) (*BufferSplitter, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("File too small (%d bytes)", len(data))
	}
	start := bytes.Index(data, MAGIC)
	if start != 0 {
		return nil, fmt.Errorf("Invalid Magic %v", data[:4])
	}
	return &BufferSplitter{data}, nil
}

func (b *BufferSplitter) Next() (bool, []byte, error) {
	if len(b.data) == 0 {
		return false, []byte{}, io.EOF
	}
	b.data = b.data[len(MAGIC):]
	is_orig := (b.data[0] & FLOW_ORIG) == FLOW_ORIG
	//fmt.Printf("Next byte is %d. is_orig=%v\n", b.data[0], is_orig)
	//skip is_orig
	b.data = b.data[1:]
	end := bytes.Index(b.data, MAGIC)
	if end == -1 {
		end = len(b.data)
	}
	//fmt.Printf("end is %d\n", end)
	payload := b.data[:end]
	b.data = b.data[end:]
	return is_orig, payload, nil
}

func expand(r io.Reader, w *pcapgo.Writer, version int) (int, error) {
	//just slurp it up
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return 0, err
	}
	b, err := NewBufferSplitter(data)
	if err != nil {
		return 0, err
	}
	totalPackets := 0
	start := time.Now()
	ts := start

	sMac, _ := net.ParseMAC("00:00:00:00:00:01")
	dMac, _ := net.ParseMAC("00:00:00:00:00:02")

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	eth := layers.Ethernet{
		SrcMAC: sMac,
		DstMAC: dMac,
		//TODO: FIXME: determine automatically
		EthernetType: layers.EthernetTypeIPv6,
	}

	for {
		ts = ts.Add(time.Duration(200) * time.Millisecond)
		_, payload, err := b.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return totalPackets, err
		}

		// If the user didn't set a version, use the one from
		// from the payload.
		payload_version := version
		if payload_version == 0 {
			payload_version = int(payload[0] & 0xF0 >> 4)
		}

		if payload_version == 4 {
			eth.EthernetType = layers.EthernetTypeIPv4
		} else {
			eth.EthernetType = layers.EthernetTypeIPv6
		}

		buf := gopacket.NewSerializeBuffer()
		/*
			err = eth.SerializeTo(buf, opts)
			if err != nil {
				return totalPackets, fmt.Errorf("eth.SerializeTo: %w", err)
			}
			bytes, err := buf.AppendBytes(len(payload))
			if err != nil {
				return totalPackets, fmt.Errorf("buf.Apppend: %w", err)
			}
			copy(bytes, payload)
		*/
		gopacket.SerializeLayers(buf, opts,
			&eth,
			gopacket.Payload(payload),
		)

		packetData := buf.Bytes()

		ci := gopacket.CaptureInfo{
			Timestamp:     ts,
			CaptureLength: len(packetData),
			Length:        len(packetData),
		}

		err = w.WritePacket(ci, packetData)
		log.Printf("Wrote packet of length %d with version %d", len(packetData), payload_version)
		if err != nil {
			return totalPackets, fmt.Errorf("Error writing packet %w", err)
		}
		totalPackets += 1
	}
	return totalPackets, nil
}

func main() {
	versionFlag := flag.Int("version", 0, "The IP version to use set. Use 0 for payload detected.")
	flag.Parse()

	if len(flag.Args()) != 2 {
		fmt.Printf("Usage: %s infile outfile\n %v", os.Args[0], flag.Args())
		os.Exit(1)
	}

	input := flag.Args()[0]
	output := flag.Args()[1]

	if input == output {
		log.Fatalf("Input and output can not be the same file")
		return
	}

	inf, err := os.Open(input)
	if err != nil {
		log.Fatalf("Can't open input: %v", err)
		return
	}
	defer inf.Close()

	outf, err := os.Create(output)
	if err != nil {
		log.Fatalf("Can't open output: %v", err)
		return
	}

	w := pcapgo.NewWriter(outf)
	w.WriteFileHeader(65536, layers.LinkTypeEthernet)

	packets, err := expand(inf, w, *versionFlag)

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%d packets rewritten", packets)
}
