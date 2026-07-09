// extractor/sysfs.go
package extractor

import (
	"os"
	"path/filepath"
	"strings"
)

func ExtractFromSysfs() []PodContainerPair {
	dirs := []string{
		"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice",
		"/sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice",
	}
	var results []PodContainerPair
	for _, base := range dirs {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || (!strings.HasPrefix(entry.Name(), "kubepods-burstable-pod") && !strings.HasPrefix(entry.Name(), "kubepods-besteffort-pod")) {
				continue
			}
			name := entry.Name()
			podUID := ""
			if strings.HasPrefix(name, "kubepods-burstable-pod") {
				podUID = strings.TrimPrefix(name, "kubepods-burstable-pod")
			} else {
				podUID = strings.TrimPrefix(name, "kubepods-besteffort-pod")
			}
			podUID = strings.ReplaceAll(strings.TrimSuffix(podUID, ".slice"), "_", "-")
			subPath := filepath.Join(base, entry.Name())
			inner, err := os.ReadDir(subPath)
			if err != nil {
				continue
			}
			for _, f := range inner {
				if strings.HasPrefix(f.Name(), "cri-containerd-") {
					containerID := strings.TrimSuffix(strings.TrimPrefix(f.Name(), "cri-containerd-"), ".scope")
					results = append(results, PodContainerPair{PodUID: podUID, ContainerID: containerID})
				}
			}
		}
	}
	return results
}
