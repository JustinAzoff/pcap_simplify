package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

type PcapPacketWriter struct {
	file   *os.File
	writer *pcapgo.Writer
}

func (w *PcapPacketWriter) WritePacketData(data []byte) error {
	info := gopacket.CaptureInfo{
		Timestamp:     time.Now(), // a bit cheap
		CaptureLength: len(data),
		Length:        len(data),
	}
	return w.writer.WritePacket(info, data)
}

func (w *PcapPacketWriter) Close() {
	w.file.Close()
}

func expand(r io.Reader, output string, port int) (int, error) {
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
	log.Printf("Writing pcap to %s", output)
	var handle PacketWriter
	if strings.HasPrefix(output, "file://") {
		fn := strings.TrimPrefix(output, "file://")
		f, err := os.Create(fn)
		if err != nil {
			log.Fatal(err)
		}
		writer := pcapgo.NewWriter(f)
		writer.WriteFileHeader(65536, layers.LinkTypeEthernet)
		handle = &PcapPacketWriter{
			file:   f,
			writer: writer,
		}
	} else {
		handle, err = pcap.OpenLive(output, 65536, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer handle.Close()
	t, err := NewTCPPacketGenerator(handle)
	if err != nil {
		log.Fatalf("Failed: %w", err)
	}
	t.Connect(0, port)
	var pl []byte
	for {
		is_orig, payload, err := b.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return totalPackets, err
		}
		totalPackets++
		for len(payload) > 0 {
			if len(payload) > 1400 {
				pl = payload[0:1400]
			} else {
				pl = payload
			}
			log.Printf("is_orig %v sending %d bytes\n", is_orig, len(pl))
			t.Write(pl, is_orig, false)
			payload = payload[len(pl):len(payload)]
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(1 * time.Second)
	t.Close()
	return totalPackets, nil
}

func main() {
	flag.Parse()

	if len(flag.Args()) != 3 {
		fmt.Printf("Usage: %s infile interface_name|file://name.pcap port\n", os.Args[0])
		fmt.Printf("\nThis streams the packets to network interface on the port specified, and\n")
		fmt.Printf("will need to be captured by tcpdump/wireshark/etc.\n")
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

	port, err := strconv.Atoi(flag.Args()[2])
	if err != nil {
		log.Fatalf("Port argument needs to be an integer value")
		return
	}

	packets, err := expand(inf, output, port)

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%d packets rewritten", packets)
}
