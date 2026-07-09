package discover

// // Container represents a discovered container
// type Container struct {
// 	PID     int    // Process ID
// 	Name    string // Container name (best effort)
// 	Runtime string // Runtime type (docker/containerd/crio/unknown)
// 	MountNS string // Mount namespace ID
// 	Cgroup  string // Cgroup identifier
// }

type Container struct {
    // Host/process view
    PID        int
    Runtime    string // "containerd", "docker", "crio", "unknown"
    MountNS    string // e.g. 4026532403
    Cgroup     string

    // Image/container view
    ContainerID string // full or short
    ContainerName string
    ImageID     string // sha256:...
    ImageRef    string // repo:tag (best-effort)

    // Kubernetes/CRI view (if present)
    PodID       string
    PodName     string
    Namespace   string // k8s namespace
}

// Provider defines the interface for container discovery
type Provider interface {
	Name() string
	Discover() ([]*Container, error)
	IsAvailable() bool
}