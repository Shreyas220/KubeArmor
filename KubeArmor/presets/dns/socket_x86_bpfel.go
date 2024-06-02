// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package dns

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSocket returns the embedded CollectionSpec for socket.
func loadSocket() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SocketBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load socket: %w", err)
	}

	return spec, err
}

// loadSocketObjects loads socket and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*socketObjects
//	*socketPrograms
//	*socketMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSocketObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSocket()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// socketSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketSpecs struct {
	socketProgramSpecs
	socketMapSpecs
}

// socketSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketProgramSpecs struct {
	SimpleSocketHandler *ebpf.ProgramSpec `ebpf:"simple_socket_handler"`
}

// socketMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type socketMapSpecs struct {
	SharedMap    *ebpf.MapSpec `ebpf:"shared_map"`
	SocketEvents *ebpf.MapSpec `ebpf:"socket_events"`
}

// socketObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSocketObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketObjects struct {
	socketPrograms
	socketMaps
}

func (o *socketObjects) Close() error {
	return _SocketClose(
		&o.socketPrograms,
		&o.socketMaps,
	)
}

// socketMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSocketObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketMaps struct {
	SharedMap    *ebpf.Map `ebpf:"shared_map"`
	SocketEvents *ebpf.Map `ebpf:"socket_events"`
}

func (m *socketMaps) Close() error {
	return _SocketClose(
		m.SharedMap,
		m.SocketEvents,
	)
}

// socketPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSocketObjects or ebpf.CollectionSpec.LoadAndAssign.
type socketPrograms struct {
	SimpleSocketHandler *ebpf.Program `ebpf:"simple_socket_handler"`
}

func (p *socketPrograms) Close() error {
	return _SocketClose(
		p.SimpleSocketHandler,
	)
}

func _SocketClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed socket_x86_bpfel.o
var _SocketBytes []byte
