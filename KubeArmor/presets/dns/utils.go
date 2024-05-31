package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func (p *Dnspreset) load_kprobe() error {
	pinpath := "/sys/fs/bpf"
	fn := "udp_sendmsg"
	objs := dnsObjects{}
	p.Dnskprobeobj = objs

	_, err := link.Kprobe(fn, objs.IgUdpSendmsg, nil)
	if err != nil {
		log.Fatalf("err opening kprobe: %s", err)
		return err
	}

	if err := loadDnsObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		p.Logger.Errf("err loading Dns objects: %v", err)
		return err
	}
	return nil
}

func (p *Dnspreset) AttachSocket(pid int, netns uint32, containerid string) {
	pinpath := "/sys/fs/bpf"

	objs := socketObjects{}
	spec, err := loadSocket()
	if err != nil {
		return
	}
	sock, _, err := p.openRawSock(pid, containerid)
	if err != nil {
		log.Fatalf("creating map: %s", err)
	}

	consts := map[string]interface{}{
		"current_netns": netns,
	}
	if err := spec.RewriteConstants(consts); err != nil {
		p.Logger.Errf("RewriteConstants while attaching to pid %d err: %s ", pid, err)
		return
	}

	if err = spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}); err != nil {
		p.Logger.Errf("err loading ebpf program: %s", err)
		return
	}

	if err := syscall.SetsockoptInt(sock, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, objs.SimpleSocketHandler.FD()); err != nil {
		p.Logger.Errf("attaching BPF program: %s", err)
	}

	rd, err := ringbuf.NewReader(objs.SocketEvents)
	// rd, err := perf.NewReader(objs.SocketPerfEvent, 4096)
	if err != nil {
		p.Logger.Errf("opening ringbuf reader: %s", err)
	}
	dnsobjmap := DnsSocketObjs{}
	dnsobjmap.RingBuf = rd
	dnsobjmap.Objs = objs
	dnsobjmap.SockFd = sock
	dnsobjmap.Netns = netns
	dnsobjmap.Containerids = []string{containerid}
	p.DnsSocketObjs[netns] = dnsobjmap

}

func (p *Dnspreset) openRawSock(pid int, containerid string) (int, int, error) {
	var netnamespace int

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origns, _ := netns.Get()
	defer origns.Close()

	netnsHandle, err := GetNetnsFromPid(pid)
	if err != nil {
		return -1, -1, err
	}
	defer netnsHandle.Close()

	var s unix.Stat_t
	if err := unix.Fstat(int(netnsHandle), &s); err != nil {
		fmt.Printf("\n->NS(%d)", s.Dev)
	}
	netnamespace = int(s.Ino)
	netns32 := uint32(netnamespace)

	sockobjs, ok := p.DnsSocketObjs[netns32]
	if ok {
		sockobjs.Containerids = append(sockobjs.Containerids, containerid)
		return -1, -1, errors.New("socket for this netns already created")
	}

	err = netns.Set(netnsHandle)
	if err != nil {
		return -1, -1, err
	}
	defer netns.Set(origns)

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, -1, err
	}

	sll := syscall.SockaddrLinklayer{
		Ifindex:  0,
		Protocol: htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return -1, -1, err
	}

	return sock, netnamespace, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func GetNetnsFromPid(pid int) (netns.NsHandle, error) {
	return netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", pid))
}

func getnetns(pid int) uint32 {
	pidstr := strconv.Itoa(pid)
	var netns uint32
	if data, err := os.Readlink("/proc/" + pidstr + "/ns/net"); err == nil {
		if _, err := fmt.Sscanf(data, "net:[%d]\n", &netns); err != nil {
			fmt.Println("Unable to get Netns (", pid, " ", err.Error(), ")")
			return 0
		}
	}

	return netns
}
