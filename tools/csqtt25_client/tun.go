package main

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// tunOffset is the room in front of every packet that the tun device wants
// (a virtio header on Linux, the protocol-family word on the BSDs).
const tunOffset = 16

// tunDev is a TUN interface carrying raw IP packets.
type tunDev struct {
	dev   tun.Device
	name  string
	rbufs [][]byte
	sizes []int

	wmu  sync.Mutex // Deliver is called from every stream's read loop
	wbuf []byte
}

func openTUN(name string, mtu int) (*tunDev, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	real, err := dev.Name()
	if err != nil {
		real = name
	}
	n := dev.BatchSize()
	t := &tunDev{dev: dev, name: real, rbufs: make([][]byte, n), sizes: make([]int, n), wbuf: make([]byte, tunOffset+65535)}
	for i := range t.rbufs {
		t.rbufs[i] = make([]byte, tunOffset+65535)
	}
	return t, nil
}

// read returns the next batch of IP packets — slices into the device's
// buffers, valid until the next call.
func (t *tunDev) read() ([][]byte, error) {
	for {
		n, err := t.dev.Read(t.rbufs, t.sizes, tunOffset)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		out := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			if t.sizes[i] > 0 {
				out = append(out, t.rbufs[i][tunOffset:tunOffset+t.sizes[i]])
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
}

// write hands one IP packet to the kernel.
func (t *tunDev) write(p []byte) error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if len(p) > len(t.wbuf)-tunOffset {
		return fmt.Errorf("packet of %d bytes exceeds the tun buffer", len(p))
	}
	copy(t.wbuf[tunOffset:], p)
	_, err := t.dev.Write([][]byte{t.wbuf[:tunOffset+len(p)]}, tunOffset)
	return err
}

func (t *tunDev) close() {
	_ = t.dev.Close()
	destroyTUN(t.name)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
