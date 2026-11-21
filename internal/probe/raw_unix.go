//go:build unix

package probe

import "syscall"

// rawSocketsAvailable reports whether this process may open a raw socket.
// That is what nmap needs for SYN scans, ICMP and ARP probes.
func rawSocketsAvailable() bool {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return false
	}
	_ = syscall.Close(fd)
	return true
}
