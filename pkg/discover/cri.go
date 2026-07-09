package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type CRIProvider struct {
	verbose bool
	// Cache for pod metadata to avoid duplicate inspectp calls
	podCache map[string]podMeta
	podMutex sync.RWMutex
}

type podMeta struct {
	name      string
	namespace string
}

func NewCRIProvider(verbose bool) *CRIProvider {
	return &CRIProvider{
		verbose:  verbose,
		podCache: make(map[string]podMeta),
	}
}

func (p *CRIProvider) Name() string {
	return "cri"
}

func (p *CRIProvider) IsAvailable() bool {
	_, err := exec.LookPath("crictl")
	return err == nil
}

func (p *CRIProvider) Discover() ([]*Container, error) {
	// Get all containers with their basic info
	containers, err := p.getAllContainers()
	if err != nil {
		return nil, fmt.Errorf("failed to get containers: %v", err)
	}

	// Get all running tasks with PIDs in a batch call
	taskPIDs, err := p.getBatchTaskPIDs(containers)
	if err != nil {
		return nil, fmt.Errorf("failed to get task PIDs: %v", err)
	}

	// Build results
	var results []*Container
	seenPIDs := map[int]struct{}{}

	for _, c := range containers {
		pid, ok := taskPIDs[c.ID]
		if !ok || pid <= 0 {
			continue
		}
		if _, dup := seenPIDs[pid]; dup {
			continue
		}

		// Get pod metadata (cached)
		podName, namespace := p.getCachedPodMeta(c.PodSandboxID)

		// Get container name from metadata or labels
		containerName := c.getContainerName()

		// Also try to get pod name from labels if not found in pod metadata
		if podName == "" {
			if labelPodName := c.Labels["io.kubernetes.pod.name"]; labelPodName != "" {
				podName = labelPodName
			}
		}

		// Also try to get namespace from labels if not found in pod metadata
		if namespace == "" {
			if labelNamespace := c.Labels["io.kubernetes.pod.namespace"]; labelNamespace != "" {
				namespace = labelNamespace
			}
		}

		// Build container entry with focus on k8s metadata
		entry := &Container{
			PID:           pid,
			Runtime:       "containerd", // Default assumption for CRI
			MountNS:       getMountNamespace(pid),
			Cgroup:        getCgroupInfo(pid),
			ContainerID:   c.ID,
			ContainerName: containerName,
			ImageRef:      c.Image.Image,
			ImageID:       c.ImageRef,
			PodID:         c.PodSandboxID,
			PodName:       podName,
			Namespace:     namespace,
		}

		results = append(results, entry)
		seenPIDs[pid] = struct{}{}
	}

	return results, nil
}

type criContainer struct {
	ID           string `json:"id"`
	PodSandboxID string `json:"podSandboxId"`
	Metadata     *struct {
		Name    string `json:"name"`
		Attempt int64  `json:"attempt"`
	} `json:"metadata"`
	Image struct {
		Image string `json:"image"`
	} `json:"image"`
	ImageRef    string            `json:"imageRef"`
	State       string            `json:"state"`
	CreatedAt   string            `json:"createdAt"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

func (c *criContainer) getContainerName() string {
	// Priority order for container name:
	// 1. Kubernetes container name from labels
	// 2. Metadata name
	// 3. Empty string
	
	if name := c.Labels["io.kubernetes.container.name"]; name != "" {
		return name
	}
	
	if c.Metadata != nil && c.Metadata.Name != "" {
		return c.Metadata.Name
	}
	
	return ""
}

func (p *CRIProvider) getAllContainers() ([]*criContainer, error) {
	// Only get running containers since we need PIDs
	out, err := exec.Command("crictl", "ps", "-o", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("crictl ps failed: %v", err)
	}

	var resp struct {
		Containers []*criContainer `json:"containers"`
	}

	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse crictl ps json: %v", err)
	}

	return resp.Containers, nil
}

// OPTIMIZATION: Use concurrent inspect calls with worker pool
func (p *CRIProvider) getBatchTaskPIDs(containers []*criContainer) (map[string]int, error) {
	const maxWorkers = 10 // Limit concurrent crictl calls
	
	jobs := make(chan *criContainer, len(containers))
	results := make(chan pidResult, len(containers))
	
	// Start workers
	var wg sync.WaitGroup
	numWorkers := maxWorkers
	if len(containers) < maxWorkers {
		numWorkers = len(containers)
	}
	
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for container := range jobs {
				pid, err := p.inspectContainerPID(container.ID)
				results <- pidResult{
					containerID: container.ID,
					pid:         pid,
					err:         err,
				}
			}
		}()
	}

	// Send jobs - only running containers should have PIDs
	go func() {
		defer close(jobs)
		for _, container := range containers {
			if strings.ToUpper(container.State) == "CONTAINER_RUNNING" {
				jobs <- container
			}
		}
	}()

	// Collect results
	pids := make(map[string]int)
	go func() {
		wg.Wait()
		close(results)
	}()

	for result := range results {
		if result.err == nil && result.pid > 0 {
			pids[result.containerID] = result.pid
		} else if p.verbose && result.err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get PID for container %s: %v\n", result.containerID, result.err)
		}
	}

	return pids, nil
}

type pidResult struct {
	containerID string
	pid         int
	err         error
}

// Enhanced PID extraction that looks in multiple locations
func (p *CRIProvider) inspectContainerPID(containerID string) (int, error) {
	out, err := exec.Command("crictl", "inspect", containerID).Output()
	if err != nil {
		return 0, err
	}

	// Parse full JSON to access all possible PID locations
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		return 0, err
	}

	// Try multiple locations where the host PID might be stored
	pidLocations := [][]string{
		{"info", "pid"},           // Most common location
		{"status", "pid"},         // Alternative location
		{"info", "process", "pid"}, // Some runtimes
		{"status", "process", "pid"},
		{"info", "runtimeSpec", "process", "pid"},
		{"status", "runtimeSpec", "process", "pid"},
	}

	for _, path := range pidLocations {
		if pid := getNestedInt(v, path...); pid > 1 { // Ignore PID 1 as it's likely container-internal
			return pid, nil
		}
	}

	// Fallback: search recursively for any "pid" field that's > 1
	if pid := findIntDeepFiltered(v, "pid", func(pid int) bool { return pid > 1 }); pid > 0 {
		return pid, nil
	}

	// Last resort: try string-based search for patterns that look like host PIDs
	if pid := p.extractHostPIDFast(string(out)); pid > 1 {
		return pid, nil
	}

	return 0, fmt.Errorf("host pid not found")
}

// getNestedInt navigates nested map structure to find an integer value
func getNestedInt(data map[string]any, path ...string) int {
	current := data
	for i, key := range path {
		if i == len(path)-1 {
			// Last key, try to extract int
			if val, exists := current[key]; exists {
				switch t := val.(type) {
				case float64:
					return int(t)
				case int:
					return t
				case string:
					if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
						return n
					}
				}
			}
			return 0
		}
		// Navigate deeper
		if next, exists := current[key]; exists {
			if nextMap, ok := next.(map[string]any); ok {
				current = nextMap
			} else {
				return 0
			}
		} else {
			return 0
		}
	}
	return 0
}

// Enhanced fast PID extraction looking for larger PIDs
func (p *CRIProvider) extractHostPIDFast(jsonStr string) int {
	// Look for "pid": number patterns, but prioritize larger numbers
	patterns := []string{
		`"pid":`,
		`"pid" :`,
	}

	var bestPid int
	for _, pattern := range patterns {
		start := 0
		for {
			idx := strings.Index(jsonStr[start:], pattern)
			if idx < 0 {
				break
			}
			idx += start
			
			// Find the number after the colon
			numStart := idx + len(pattern)
			for numStart < len(jsonStr) && (jsonStr[numStart] == ' ' || jsonStr[numStart] == '\t') {
				numStart++
			}
			
			numEnd := numStart
			for numEnd < len(jsonStr) && (jsonStr[numEnd] >= '0' && jsonStr[numEnd] <= '9') {
				numEnd++
			}
			
			if numEnd > numStart {
				if pid, err := strconv.Atoi(jsonStr[numStart:numEnd]); err == nil && pid > 1 {
					// Prefer higher PIDs as they're more likely to be host PIDs
					if pid > bestPid {
						bestPid = pid
					}
				}
			}
			start = idx + len(pattern)
		}
	}
	return bestPid
}

// Cache pod metadata to avoid duplicate inspectp calls
func (p *CRIProvider) getCachedPodMeta(podSandboxID string) (string, string) {
	if podSandboxID == "" {
		return "", ""
	}

	// Check cache first
	p.podMutex.RLock()
	if meta, exists := p.podCache[podSandboxID]; exists {
		p.podMutex.RUnlock()
		return meta.name, meta.namespace
	}
	p.podMutex.RUnlock()

	// Not in cache, fetch it
	podName, namespace := p.getPodMeta(podSandboxID)
	
	// Cache the result (even if empty to avoid repeated failures)
	p.podMutex.Lock()
	p.podCache[podSandboxID] = podMeta{
		name:      podName,
		namespace: namespace,
	}
	p.podMutex.Unlock()

	return podName, namespace
}

func (p *CRIProvider) getPodMeta(podSandboxID string) (string, string) {
	out, err := exec.Command("crictl", "inspectp", "-o", "json", podSandboxID).Output()
	if err != nil {
		if p.verbose {
			fmt.Fprintf(os.Stderr, "Failed to inspect pod %s: %v\n", podSandboxID, err)
		}
		return "", ""
	}

	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		return "", ""
	}

	var podName, namespace string
	
	// Try status.metadata first (most common location)
	if status, ok := v["status"].(map[string]any); ok {
		if md, ok := status["metadata"].(map[string]any); ok {
			if n, ok := md["name"].(string); ok {
				podName = n
			}
			if ns, ok := md["namespace"].(string); ok {
				namespace = ns
			}
		}
	}
	
	return podName, namespace
}

// Helper functions
func getMountNamespace(pid int) string {
	link, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", pid))
	if err != nil {
		return "unknown"
	}
	start := strings.Index(link, "[")
	end := strings.Index(link, "]")
	if start >= 0 && end > start {
		return link[start+1 : end]
	}
	return link
}

func getCgroupInfo(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "unknown"
	}
	lines := strings.Split(string(data), "\n")
	for _, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		parts := strings.SplitN(ln, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := parts[2]
		segs := strings.Split(path, "/")
		last := segs[len(segs)-1]
		if last == "" && len(segs) > 1 {
			last = segs[len(segs)-2]
		}
		if last != "" {
			if len(last) > 16 {
				return last[:16]
			}
			return last
		}
	}
	return "unknown"
}

// findIntDeepFiltered searches recursively with a filter function
func findIntDeepFiltered(v any, needle string, filter func(int) bool) int {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == needle {
				switch vv := val.(type) {
				case float64:
					if pid := int(vv); filter(pid) {
						return pid
					}
				case int:
					if filter(vv) {
						return vv
					}
				case string:
					if n, err := strconv.Atoi(strings.TrimSpace(vv)); err == nil && filter(n) {
						return n
					}
				}
			}
			if n := findIntDeepFiltered(val, needle, filter); n > 0 {
				return n
			}
		}
	case []any:
		for _, it := range t {
			if n := findIntDeepFiltered(it, needle, filter); n > 0 {
				return n
			}
		}
	}
	return 0
}

// findIntDeep searches recursively for a key and returns the first int-like value found
func findIntDeep(v any, needle string) int {
	return findIntDeepFiltered(v, needle, func(pid int) bool { return pid > 0 })
}