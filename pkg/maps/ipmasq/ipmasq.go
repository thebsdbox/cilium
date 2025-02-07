// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipmasq

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapNameIPv4    = "cilium_ipmasq_v4"
	MaxEntriesIPv4 = 16384
	MapNameIPv6    = "cilium_ipmasq_v6"
	MaxEntriesIPv6 = 16384
)

type Key4 struct {
	PrefixLen uint32
	Address   types.IPv4
}

func (k *Key4) String() string  { return fmt.Sprintf("%s", k.Address) }
func (k *Key4) New() bpf.MapKey { return &Key4{} }

type Key6 struct {
	PrefixLen uint32
	Address   types.IPv6
}

func (k *Key6) String() string  { return fmt.Sprintf("%s", k.Address) }
func (k *Key6) New() bpf.MapKey { return &Key6{} }

type Value struct {
	Pad uint8 // not used
}

func (v *Value) String() string    { return "" }
func (v *Value) New() bpf.MapValue { return &Value{} }

var (
	ipMasq4Map *bpf.Map
	onceIPv4   sync.Once
	ipMasq6Map *bpf.Map
	onceIPv6   sync.Once
)

func IPMasq4Map() *bpf.Map {
	onceIPv4.Do(func() {
		ipMasq4Map = bpf.NewMap(
			MapNameIPv4,
			ebpf.LPMTrie,
			&Key4{},
			&Value{},
			MaxEntriesIPv4,
			bpf.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapNameIPv4))
	})
	return ipMasq4Map
}

func IPMasq6Map() *bpf.Map {
	onceIPv6.Do(func() {
		ipMasq6Map = bpf.NewMap(
			MapNameIPv6,
			ebpf.LPMTrie,
			&Key6{},
			&Value{},
			MaxEntriesIPv6,
			bpf.BPF_F_NO_PREALLOC,
		).WithCache().WithPressureMetric().
			WithEvents(option.Config.GetEventBufferConfig(MapNameIPv6))
	})
	return ipMasq6Map
}

type IPMasqBPFMap struct{}

func (*IPMasqBPFMap) Update(cidr net.IPNet) error {
	if ip.IsIPv4(cidr.IP) {
		return IPMasq4Map().Update(keyIPv4(cidr), &Value{})
	} else {
		return IPMasq6Map().Update(keyIPv6(cidr), &Value{})
	}
}

func (*IPMasqBPFMap) Delete(cidr net.IPNet) error {
	if ip.IsIPv4(cidr.IP) {
		return IPMasq4Map().Delete(keyIPv4(cidr))
	} else {
		return IPMasq6Map().Delete(keyIPv6(cidr))
	}
}

func (*IPMasqBPFMap) Dump() ([]net.IPNet, error) {
	cidrs := []net.IPNet{}
	if ipMasq4Map != nil {
		if err := ipMasq4Map.DumpWithCallback(
			func(keyIPv4 bpf.MapKey, _ bpf.MapValue) {
				cidrs = append(cidrs, keyToIPNetIPv4(keyIPv4.(*Key4)))
			}); err != nil {
			return nil, err
		}
	}
	if ipMasq6Map != nil {
		if err := ipMasq6Map.DumpWithCallback(
			func(keyIPv6 bpf.MapKey, _ bpf.MapValue) {
				cidrs = append(cidrs, keyToIPNetIPv6(keyIPv6.(*Key6)))
			}); err != nil {
			return nil, err
		}
	}
	return cidrs, nil
}

func keyIPv4(cidr net.IPNet) *Key4 {
	ones, _ := cidr.Mask.Size()
	key := &Key4{PrefixLen: uint32(ones)}
	copy(key.Address[:], cidr.IP.To4())
	return key
}

func keyToIPNetIPv4(key *Key4) net.IPNet {
	var (
		cidr net.IPNet
		ip   types.IPv4
	)

	cidr.Mask = net.CIDRMask(int(key.PrefixLen), 32)
	key.Address.DeepCopyInto(&ip)
	cidr.IP = ip.IP()

	return cidr
}

func keyIPv6(cidr net.IPNet) *Key6 {
	ones, _ := cidr.Mask.Size()
	key := &Key6{PrefixLen: uint32(ones)}
	copy(key.Address[:], cidr.IP.To16())
	return key
}

func keyToIPNetIPv6(key *Key6) net.IPNet {
	var (
		cidr net.IPNet
		ip   types.IPv6
	)

	cidr.Mask = net.CIDRMask(int(key.PrefixLen), 128)
	key.Address.DeepCopyInto(&ip)
	cidr.IP = ip.IP()

	return cidr
}
