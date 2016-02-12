// +build linux

package proc

import (
	"bytes"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
)

const (
	None  = 0x0
	Read  = 0x1
	Write = 0x2
	Exec  = 0x4
)

// Map is a mapped memory region, found in /proc/$$/maps
// See: mmap(2)
type Map struct {
	Start   uintptr // Beginning memory address.
	End     uintptr // Ending memory address.
	Perms   uint8   // Memory protection bitmask.
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

const (
	Stack = "[stack]"
	Heap  = "[heap]"
	VSDO  = "[vsdo]"
)

// IsStack returns true if the mapping points to the stack.
func (m Map) IsStack() bool {
	return m.Path == "[stack]"
}

// IsHeap returns true if the mapping points to the heap.
func (m Map) IsHeap() bool {
	return m.Path == "[heap]"
}

// IsVSDO returns true if the mapping points to a virtual dynamically linked
// shared object.
func (m Map) IsVSDO() bool {
	return m.Path == "[vsdo]"
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

// ParseMaps parses /proc/$$/maps into a useable data structure.
func ParseMaps() (maps []Map) {

	lines := bytes.Split(slurp(filename()), []byte{'\n'})

	var m Map
	for _, line := range lines {
		m.read(line)
		maps = append(maps, m)
	}

	return maps
}

func slurp(name string) []byte {
	file, err := os.Open(name)
	if err != nil {
		log.Fatalln(err)
	}
	defer file.Close()
	buf, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalln(err)
	}
	return buf
}

// hexToUintptr converts b into a uintptr.
// It's optimized to assume the input will not be invalid.
// (I.e., that /proc/$$/maps won't produce a garbage value.)
func hexToUintptr(b []byte) (n uintptr) {
	for _, d := range b {
		switch {
		case '0' <= d && d <= '9':
			n += uintptr(d - '0')
		case 'a' <= d && d <= 'z':
			n += uintptr(d - 'a' + 10)
		case 'A' <= d && d <= 'Z':
			n += uintptr(d - 'A' + 10)
		default:
			return 0
		}
		n *= 16
	}
	return n
}

// parseUint parses b into a uint64. See hexToUintptr for more.
func parseUint(b []byte) (n uint64) {
	for _, d := range b {
		switch {
		case '0' <= d && d <= '9':
			n += uint64(d - '0')
		case 'a' <= d && d <= 'z':
			n += uint64(d - 'a' + 10)
		case 'A' <= d && d <= 'Z':
			n += uint64(d - 'A' + 10)
		default:
			return 0
		}
		n *= 10
	}
	return n
}

func filename() string {
	return "/proc/" + strconv.Itoa(os.Getpid()) + "/maps"
}
