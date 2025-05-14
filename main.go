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
	"github.com/cilium/ebpf/rlimit"
	"github.com/segmentio/kafka-go"
)

//go:embed bpf/netflow.bpf.c
var bpfCode string

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

	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader([]byte(bpfCode)))
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	// Set up TC qdisc (clsact)
	iface := "eth0" // Replace with your network interface
	if err := setupTC(iface); err != nil {
		log.Fatalf("Failed to set up TC qdisc: %v", err)
	}
	defer cleanupTC(iface)

	// Attach TC ingress and egress hooks
	ingressProg := coll.Programs["tc_ingress_func"]
	egressProg := coll.Programs["tc_egress_func"]

	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   ingressProg,
		Interface: iface,
		Direction: "ingress",
	})
	if err != nil {
		log.Fatalf("Failed to attach TC ingress: %v", err)
	}
	defer ingressLink.Close()

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Program:   egressProg,
		Interface: iface,
		Direction: "egress",
	})
	if err != nil {
		log.Fatalf("Failed to attach TC egress: %v", err)
	}
	defer egressLink.Close()

	// Open ring buffer
	rb := coll.Maps["netflow_ringbuf"]
	ringBuf, err := ebpf.NewRingBuf(rb, nil)
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
