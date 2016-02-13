// +build linux,amd64

package proc

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	None  Perms = 0x0
	Read  Perms = 0x1
	Write Perms = 0x2
	Exec  Perms = 0x4

	priv Perms = 0x8
)

const (
	Stack    = "[stack]"
	Heap     = "[heap]"
	VSDO     = "[vsdo]"
	VSyscall = "[vsyscall]"
	VVar     = "[vvar]"
)

// Map is a mapped memory region, found in /proc/$$/maps
// See: mmap(2)
type Map struct {
	Start   uintptr // Beginning memory address.
	End     uintptr // Ending memory address.
	Perms   Perms   // Memory protection bitmask.
	Private bool    // true if the mapping is private (copy on write).
	Offset  uintptr // Offset where mapping begins.
	Dev     struct {
		Maj, Min uint64
	} // Major and minor device number.
	Inode uint64 // If mapped from a file, the file's inode.

	// If mapped from a file, the file's path. Special values
	// include [stack], [heap], and [vsdo]. See related methods.
	Path string
}

// Perms are mmap(2)'s memory prot bitmask.
type Perms int

func (p Perms) String() string {
	b := [4]byte{'-', '-', '-', 's'}
	if p&None == 0 {
		if p&Read != 0 {
			b[0] = 'r'
		}
		if p&Write != 0 {
			b[1] = 'w'
		}
		if p&Exec != 0 {
			b[2] = 'x'
		}
	}
	if p&priv != 0 {
		b[3] = 'p'
	}
	return string(b[:])
}

func (m Map) String() string {
	perms := m.Perms
	if m.Private {
		perms |= priv
	}
	return fmt.Sprintf("%0.8x-%0.8x %s %0.8x %d:%d %d %s",
		m.Start, m.End, perms, m.Offset,
		m.Dev.Maj, m.Dev.Min, m.Inode, m.Path,
	)
}

// IsStack returns true if the mapping points to the stack.
func (m Map) IsStack() bool {
	return m.Path == Stack
}

// IsHeap returns true if the mapping points to the heap.
func (m Map) IsHeap() bool {
	return m.Path == Heap
}

// IsVSDO returns true if the mapping points to a virtual dynamically linked
// shared object.
func (m Map) IsVSDO() bool {
	return m.Path == VSDO
}

// IsVSyscall returns true if the mapping points to a page containing a kernel
// syscall mapped into userspace.
func (m Map) IsVSyscall() bool {
	return m.Path == VSyscall
}

// IsVVar returns true if the mapping points to a page containing a kernel
// variable mapped into userspace.
func (m Map) IsVVar() bool {
	return m.Path == VVar
}

// ErrVersion is returned from the ThreadID method if the mapping
// does not have a thread ID. (Usually means the linux version is
// too old.)
var ErrVersion = errors.New("thread id needs linux >= 3.4")

// ThreadID returns the thread (mapping) ID that corresponds
// to the /proc/$$/task/[id] path. It returns an error if the
// mapping is either not a stack or does not have a thread id.
func (m Map) ThreadID() (int, error) {
	if !m.IsStack() {
		return 0, ErrVersion
	}
	i := strings.IndexByte(m.Path, ':')
	if i < 0 {
		return 0, ErrVersion
	}
	return strconv.Atoi(m.Path[i+1 : len(m.Path)-1])
}

// read returns a boolean indicating whether or not the read was
// successful.
func (m *Map) read(p []byte) bool {
	if p == nil || len(p) == 0 {
		return false
	}

	parts := bytes.Split(p, []byte{' '})

	// 6 parts minimum, but no max since sometimes
	// there's a big space between inode and path.
	if len(parts) < 6 {
		return false
	}

	// Convert the address ranges from hex to uintptr.
	addr := bytes.Split(parts[0], []byte{'-'})
	m.Start = hexToUintptr(addr[0])
	m.End = hexToUintptr(addr[1])

	// Convert 'rwxp' to permissions bitmask.
	for _, c := range parts[1] {
		switch c {
		case 'r':
			m.Perms |= Read
		case 'w':
			m.Perms |= Write
		case 'x':
			m.Perms |= Exec

		// No case 's' because it defaults to false.
		case 'p':
			m.Private = true
		}
	}

	m.Offset = hexToUintptr(parts[2])

	// Split dev into Major:Minor parts.
	dev := bytes.Split(parts[3], []byte{':'})
	m.Dev.Maj = parseUint(dev[0])
	m.Dev.Min = parseUint(dev[1])

	m.Inode = parseUint(parts[4])
	m.Path = string(parts[len(parts)-1])
	return true
}

var filename = "/proc/" + strconv.Itoa(os.Getpid()) + "/maps"

// ParseMaps parses /proc/$$/maps into a useable data structure.
func ParseMaps() (maps []Map) {

	lines := bytes.Split(slurp(filename), []byte{'\n'})

	var m Map
	for _, line := range lines {
		m.read(line)
		maps = append(maps, m)
	}
	return maps
}

// Find searches through /proc/$$/maps to the find the range that holds
// pc. It returns the Map and a boolean indicating whether the Map was found.
func Find(pc uintptr) (m Map, ok bool) {
	for _, m := range ParseMaps() {
		if pc >= m.Start && pc <= m.End {
			return m, true
		}
	}
	return m, false
}

// Mprotect calls mprotect(2) on the mmapped region.
func (m Map) Mprotect(prot Perms) (err error) {
	_, _, e1 := unix.Syscall(
		unix.SYS_MPROTECT,
		uintptr(m.Start),
		uintptr(m.End-m.Start),
		uintptr(prot),
	)
	if e1 != 0 {
		return e1
	}
	return
}
