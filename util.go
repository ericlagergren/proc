// +build linux,amd64

package proc

import (
	"io/ioutil"
	"log"
	"os"
)

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
		n *= 16
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
	}
	return n
}

// parseUint parses b into a uint64. See hexToUintptr for more.
func parseUint(b []byte) (n uint64) {
	for _, d := range b {
		n *= 10
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
	}
	return n
}
