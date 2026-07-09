package utils

type PodLog struct {
	PodUID      string   `json:"pod_uid"`
	ContainerID string   `json:"container_id"`
	Logs        []string `json:"logs"`
}

type PodContainerPair struct {
	PID           int
	ContainerID   string
	ContainerName string
	PodName       string
	Namespace     string
	PodUID        string
}