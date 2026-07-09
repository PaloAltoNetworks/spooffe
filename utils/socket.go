// utils/socket.go

package utils

import "strings"

// NormalizeSocketPath ensures the socket path is prefixed with unix://
func NormalizeSocketPath(p string) string {
	if strings.HasPrefix(p, "unix://") {
		return p
	}
	return "unix://" + p
}
