//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/segmentio/kafka-go"
)

// NetFlowRecord matches the C struct netflow_record
type NetFlowRecord struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
	Packets  uint64
	Bytes    uint64
	StartTS  uint64
	EndTS    uint64
}

// NetFlowJSON for Kafka export
type NetFlowJSON struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	StartTime string `json:"start_time"`
	EndTime   string `json:"end_time"`
}

func main() {
	// Remove resource limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	objs := netflowObjects{}
	if err := loadNetflowObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	// Set up TC qdisc (clsact)
	if err := setupTC(ifaceName); err != nil {
		log.Fatalf("Failed to set up TC qdisc: %v", err)
	}
	defer cleanupTC(ifaceName)

	// Attach the program to Ingress TC.
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcIngressFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer ingressLink.Close()

	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)

	// Attach the program to Egress TC.
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcEgressFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer egressLink.Close()

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Open ring buffer
	rb := objs.NetflowRingbuf
	ringBuf, err := ringbuf.NewReader(rb)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer ringBuf.Close()

	// Initialize Kafka writer
	kafkaWriter := &kafka.Writer{
		Addr:     kafka.TCP("kafka-broker:9092"), // Replace with your Kafka broker
		Topic:    "netflow",
		Balancer: &kafka.LeastBytes{},
	}
	defer kafkaWriter.Close()

	// Handle signals for graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Process ring buffer events
	go func() {
		var record NetFlowRecord
		for {
			event, err := ringBuf.Read()
			if err != nil {
				log.Printf("Error reading ring buffer: %v", err)
				continue
			}

			// Parse NetFlow record
			if err := binary.Read(bytes.NewReader(event.RawSample), binary.LittleEndian, &record); err != nil {
				log.Printf("Error parsing record: %v", err)
				continue
			}

			// Convert to JSON
			netflowJSON := NetFlowJSON{
				SrcIP:     net.IPv4(byte(record.SrcIP>>24), byte(record.SrcIP>>16), byte(record.SrcIP>>8), byte(record.SrcIP)).String(),
				DstIP:     net.IPv4(byte(record.DstIP>>24), byte(record.DstIP>>16), byte(record.DstIP>>8), byte(record.DstIP)).String(),
				SrcPort:   record.SrcPort,
				DstPort:   record.DstPort,
				Protocol:  protocolToString(record.Protocol),
				Packets:   record.Packets,
				Bytes:     record.Bytes,
				StartTime: time.Unix(0, int64(record.StartTS)).Format(time.RFC3339),
				EndTime:   time.Unix(0, int64(record.EndTS)).Format(time.RFC3339),
			}

			// Marshal to JSON
			data, err := json.Marshal(netflowJSON)
			if err != nil {
				log.Printf("Error marshaling JSON: %v", err)
				continue
			}

			// Send to Kafka
			err = kafkaWriter.WriteMessages(context.Background(),
				kafka.Message{
					Value: data,
				},
			)
			if err != nil {
				log.Printf("Error writing to Kafka: %v", err)
			} else {
				log.Printf("Sent NetFlow record: %s", string(data))
			}
		}
	}()

	// Wait for shutdown signal
	<-stop
	log.Println("Shutting down...")
}

func protocolToString(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", proto)
	}
}

// setupTC configures the clsact qdisc for the interface
func setupTC(iface string) error {
	// Add clsact qdisc
	cmd := exec.Command("tc", "qdisc", "add", "dev", iface, "clsact")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add clsact qdisc: %v", err)
	}
	return nil
}

// cleanupTC removes the clsact qdisc
func cleanupTC(iface string) {
	cmd := exec.Command("tc", "qdisc", "del", "dev", iface, "clsact")
	if err := cmd.Run(); err != nil {
		log.Printf("Failed to delete clsact qdisc: %v", err)
	}
}
