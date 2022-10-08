//go:build exclude

package xdp

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf openspa_adk.c -- -I./headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]

	iface, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %s: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}

	defer objs.Close()

	flags := nl.XDP_FLAGS_SKB_MODE
	//flags := nl.XDP_FLAGS_DRV_MODE

	force := true
	if !force {
		// If XDP program is already linked, do not replace it.
		flags |= nl.XDP_FLAGS_UPDATE_IF_NOEXIST
	}

	if err := netlink.LinkSetXdpFdWithFlags(iface, objs.XdpOpenspaAdk.FD(), flags); err != nil {
		log.Fatalf("link set xdp failed iface %s: %s", ifaceName, err)
	}

	linkCleanup := func() {
		log.Printf("Unlinking XDP")
		if err := netlink.LinkSetXdpFdWithFlags(iface, -1, flags); err != nil {
			log.Printf("link unset xdp failed iface %s", iface)
		}
	}

	log.Printf("Attached XDP program to iface %q (index %d) (flags %d) (xdp demo id %d)", iface.Attrs().Name, iface.Attrs().Index, flags, objs.XdpOpenspaAdk.FD())
	log.Printf("Press Ctrl-C to exit and remove the program")

	if err := objs.XdpConfigMap.Put(uint32(0), uint32(22211)); err != nil {
		log.Fatalf("Failed to set key 0 on config map")
	}

	if err := objs.XdpConfigMap.Put(uint32(1), binary.BigEndian.Uint32([]byte{1, 2, 3, 4})); err != nil {
		log.Fatalf("Failed to set key 1 on config map")
	}

	if err := objs.XdpConfigMap.Put(uint32(2), binary.BigEndian.Uint32([]byte{0, 0, 0, 0})); err != nil {
		log.Fatalf("Failed to set key 2 on config map")
	}

	// Print the contents of the BPF hash map (source IP address -> packet count).
	ticker := time.NewTicker(1 * time.Second)
	go func() {
		for range ticker.C {
			s, err := formatMapContents(objs.XdpStatsMap)
			if err != nil {
				log.Printf("Error reading map: %s", err)
				continue
			}
			log.Printf("Map contents:\n%s", s)
		}
	}()

	done := make(chan bool)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, os.Kill)
	go func() {
		<-sigs
		linkCleanup()
		ticker.Stop()
		done <- true
	}()

	<-done
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key []byte
		val []bpfStatsDatarec
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		k := Action(NativeOrder.Uint32(key))

		d := bpfStatsDatarec{}

		for _, rec := range val {
			d.RxBytes += rec.RxBytes
			d.RxPackets += rec.RxPackets
		}

		sb.WriteString(fmt.Sprintf("\t%v => %v\n", k.String(), d.String()))
	}
	return sb.String(), iter.Err()
}

func (b bpfStatsDatarec) String() string {
	return fmt.Sprintf("packets: %d, bytes: %d", b.RxPackets, b.RxBytes)
}
