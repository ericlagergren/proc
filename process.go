// +build linux,amd64

package proc

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func NewProcess(pid int) Process {
	prefix := proc + strconv.Itoa(pid)
	return Process{
		prefix: prefix,
		maps:   prefix + "/maps",
		exe:    prefix + "/exe",
	}
}

type Process struct {
	prefix string
	maps   string
	exe    string
}

// ParseMaps parses /proc/$$/maps into a useable data structure.
func (p Process) ParseMaps() (maps Mapping, err error) {
	// TODO: slurp or use a reader? /proc/$$/maps shouldn't be large...
	buf, err := ioutil.ReadFile(p.maps)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(buf, []byte{'\n'})

	var m Map
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		parts := bytes.Split(line, []byte{' '})

		// 6 parts minimum, but no max since sometimes
		// there's a big space between inode and path.
		// Prior to 2.0 there was only 5, but I doubt anybody
		// has a kernel from ~2004 that runs Go.
		if len(parts) < 6 {
			return maps, errors.New("proc.ParseMaps not enough portions.")
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
			case 'p':
				m.Perms |= Priv
			case 's':
				m.Perms |= Shared
			}
		}

		m.Offset = hexToUintptr(parts[2])

		// Split dev into Major:Minor parts.
		dev := bytes.Split(parts[3], []byte{':'})
		m.Maj = parseUint(dev[0])
		m.Min = parseUint(dev[1])

		m.Inode = parseUint(parts[4])
		m.Path = string(parts[len(parts)-1])
		m.Type = p.ParseType(m.Path)
		maps = append(maps, m)
	}
	return maps, nil
}

// Find searches through /proc/$$/maps to the find the range that holds
// pc. It returns the Map and a boolean indicating whether the Map was found.
func (p Process) Find(pc uintptr) (m Map, ok bool) {
	maps, err := ParseMaps()
	if err != nil {
		return m, false
	}
	for _, m := range maps {
		if pc >= m.Start && pc <= m.End {
			return m, true
		}
	}
	return m, false
}

// ParseType parses s into a Type.
func (p Process) ParseType(s string) Type {
	if s == "" {
		return Unknown
	}

	// See if it's a special value.
	if s[0] == '[' {
		switch s {
		case "[heap]":
			return Heap
		case "[stack]":
			return Stack
		case "[vsdo]":
			return VSDO
		case "[vsyscall]":
			return VSyscall
		case "[vvar]":
			return VVar
		}

		// Fish out stack with thread IDs like [stack:1234]
		if strings.HasPrefix(s, "[stack:") && s[len(s)-1] == ']' {
			return Stack
		}
	}

	// Probably is a path.
	// We can't use filepath.Ext here because if, for example, the path is:
	// /usr/share/lib/libc.so.6
	// filepath.Ext will return ".6" which is a false negative for a .so file.

	if strings.HasSuffix(s, ".so") ||
		strings.LastIndex(s, ".so.") > 0 {
		return Lib
	}

	var stat unix.Stat_t
	if err := unix.Stat(s, &stat); err != nil {
		return Unknown
	}

	ino := stat.Ino

	err := unix.Stat(p.exe, &stat)
	if err != nil {
		return Data
	}

	if stat.Ino == ino {
		return Exe
	}
	return Unknown
}

func (p Process) ExePath() (string, error) {
	return os.Readlink(p.exe)
}
