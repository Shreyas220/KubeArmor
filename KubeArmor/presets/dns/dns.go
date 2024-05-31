package dns

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/kubearmor/KubeArmor/KubeArmor/presets"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go socket ../../BPF/dnssocket.bpf.c -- -I/usr/include/ -O2 -g
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go dns ../../BPF/dnskprobe.bpf.c -- -I/usr/include/ -O2 -g

// add check for newer kernel versions
type DnsSocketObjs struct {
	Netns        uint32
	Objs         socketObjects
	RingBuf      *ringbuf.Reader
	Containerids []string
	SockFd       int
}

type containerinfo struct {
	Pid   int
	Pidns uint32
	Mntns uint32
	Netns uint32
}

type Dnspreset struct {
	presets.BasePreset
	Containers    map[string]containerinfo
	Dnskprobeobj  dnsObjects
	Kprobe        link.Link
	Dnscontainers *ebpf.Map
	DnsSocketObjs map[uint32]DnsSocketObjs
}

type namespaceKey struct {
	pidns uint64
	mntns uint64
}

func (p *Dnspreset) RegisterPreset() {
	pinpath := "/sys/fs/bpf"

	Dnscontainermap, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 256,
		Pinning:    ebpf.PinByName,
		Name:       "dns_container_maps",
	}, ebpf.MapOptions{
		PinPath: pinpath,
	})
	if err != nil {
		p.Logger.Errf("err pining container map: %v", err)
	}

	_, err = ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    16,
		ValueSize:  48,
		MaxEntries: 128,
		Pinning:    ebpf.PinByName,
		Name:       "dns_shared_map",
	}, ebpf.MapOptions{
		PinPath: pinpath,
	})
	if err != nil {
		p.Logger.Errf("err pinning sharedmap: %v", err)
	}

	p.load_kprobe()
	p.Dnscontainers = Dnscontainermap
}

func (p *Dnspreset) RegisterContainer(container tp.Container) {
	containerInfo := containerinfo{Pid: container.Pid, Pidns: container.PidNS, Mntns: container.PidNS}
	p.Containers[container.ContainerID] = containerInfo
}

func (p *Dnspreset) updateMapin(con containerinfo) {
	key := namespaceKey{pidns: uint64(con.Pidns), mntns: uint64(con.Pidns)}
	value := uint32(1)
	if err := p.Dnscontainers.Put(key, value); err != nil {
		p.Logger.Errf("error adding container %s to outer map: %s", "", err)
	}

}

func (p *Dnspreset) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	for _, cid := range endPoint.Containers {
		container, ok := p.Containers[cid]
		if ok {
			p.updateMapin(container)
			netns := getnetns(container.Pid)
			p.AttachSocket(container.Pid, netns, cid)
		}
	}
}

func (p *Dnspreset) Destroy() error {
	if err := p.Kprobe.Close(); err != nil {
		p.Logger.Errf("error destroying kprobe %s", err.Error())
	}

	for _, value := range p.DnsSocketObjs {
		sock := value.SockFd
		unix.Close(sock)
		value.Objs.Close()
	}

	return nil
}

func (p *Dnspreset) TraceEvents() {}

func (p *Dnspreset) UnregisterContainer() {
}
