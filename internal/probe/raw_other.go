//go:build !unix

package probe

func rawSocketsAvailable() bool { return false }
