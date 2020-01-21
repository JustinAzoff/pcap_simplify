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
	"os/exec"
	"syscall"
	"time"
)

var MAGIC = []byte("\x01PKT")
var FLOW_ORIG = byte('\x01')
var FLOW_RESP = byte('\x02')

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
	is_orig := (b.data[0] == FLOW_ORIG)
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

func server(port int, pktchan <-chan []byte) error {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	log.Printf("Listening on port %d", port)
	conn, err := l.Accept()
	if err != nil {
		return err
	}
	log.Printf("Got connection")
	go io.Copy(ioutil.Discard, conn)
	for msg := range pktchan {
		log.Printf("Server writing %d bytes", len(msg))
		_, err := conn.Write(msg)
		if err != nil {
			return err
		}
	}
	conn.Close()
	return nil
}
func client(port int, pktchan <-chan []byte) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	log.Printf("Connected!")
	go io.Copy(ioutil.Discard, conn)
	for msg := range pktchan {
		log.Printf("Client writing %d bytes", len(msg))
		_, err := conn.Write(msg)
		if err != nil {
			return err
		}
	}
	conn.Close()
	return nil
}

func expand(r io.Reader, outputFilename string, port int) (int, error) {
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
	cmd := exec.Command("tcpdump", "-i", "lo", "-w", outputFilename, fmt.Sprintf("port %d", port))
	err = cmd.Start()
	if err != nil {
		return 0, err
	}

	serverPkts := make(chan []byte)
	clientPkts := make(chan []byte)

	go func() {
		err := server(port, serverPkts)
		if err != nil {
			log.Printf("Server error: %v", err)
		}
	}()
	time.Sleep(1 * time.Second)
	go func() {
		err := client(port, clientPkts)
		if err != nil {
			log.Printf("Client error: %v", err)
		}
	}()

	for {
		is_orig, payload, err := b.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return totalPackets, err
		}
		totalPackets++
		//log.Printf("is_orig %v Data is %d bytes\n", is_orig, len(payload))
		if is_orig {
			clientPkts <- payload
		} else {
			serverPkts <- payload
		}
		time.Sleep(100 * time.Millisecond)
	}
	time.Sleep(1 * time.Second)
	cmd.Process.Signal(syscall.SIGINT)
	cmd.Wait()

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

	packets, err := expand(inf, output, 443)

	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%d packets rewritten", packets)
}
