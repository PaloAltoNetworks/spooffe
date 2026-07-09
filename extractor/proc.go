// extractor/proc.go
package extractor

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var podContainerRegex = []*regexp.Regexp{
	regexp.MustCompile(`pod(?P<poduid>[a-f0-9_-]{36}).*?(?P<containerid>[a-f0-9]{64})`),
	regexp.MustCompile(`(?P<poduid>[a-f0-9\\-]{36}).*?(?P<containerid>[a-f0-9]{64})`),
	regexp.MustCompile(`(?P<containerid>[a-f0-9]{64})`),
}

func ExtractFromProcCgroup() []PodContainerPair {
	seen := make(map[PodContainerPair]struct{})
	var results []PodContainerPair
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Fatal(err)
	}

	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		cgroupFile := filepath.Join("/proc", entry.Name(), "cgroup")
		f, err := os.Open(cgroupFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) != 3 {
				continue
			}
			path := fields[2]
			for _, re := range podContainerRegex {
				match := re.FindStringSubmatch(path)
				if match != nil {
					podUID := getGroup(re, match, "poduid")
					containerID := getGroup(re, match, "containerid")
					if podUID != "" && containerID != "" {
						podUID = strings.ReplaceAll(podUID, "_", "-")
						pair := PodContainerPair{PodUID: podUID, ContainerID: containerID}
						if _, exists := seen[pair]; !exists {
							seen[pair] = struct{}{}
							results = append(results, pair)
						}
					}
				}
			}
		}
		f.Close()
	}
	return results
}

func getGroup(re *regexp.Regexp, matches []string, name string) string {
	for i, n := range re.SubexpNames() {
		if n == name {
			return matches[i]
		}
	}
	return ""
}

func isNumeric(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
