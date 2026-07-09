// cmd/list.go
package list

import (
	"fmt"
	"log"
	"os"
	"github.com/spf13/cobra"
	"spooffe/extractor"
	"spooffe/utils"
	"spooffe/pkg/discover" // Import your discover package
)

var (
	source      string
	verboseFlag bool
	wideFlag    bool
	noTrunc     bool
)

func NewListCmd() *cobra.Command {
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all pod/container pairs",
		Long:  `List all containers on the machine with support for multiple discovery methods.`,
		Run:   runList,
	}
	
	listCmd.Flags().StringVar(&source, "source", "sysfs", "Source of container data: sysfs, proc, or cri")
	listCmd.Flags().BoolVarP(&verboseFlag, "verbose", "v", false, "verbose output")
	listCmd.Flags().BoolVarP(&wideFlag, "wide", "w", false, "show additional columns (pod id, container id, image id)")
	listCmd.Flags().BoolVar(&noTrunc, "no-trunc", false, "do not truncate long fields")
	
	return listCmd
}

func runList(cmd *cobra.Command, args []string) {
	switch source {
	case "cri":
		runCRIList()
	case "proc":
		runTraditionalList("proc")
	case "sysfs":
		runTraditionalList("sysfs")
	default:
		log.Fatalf("Unknown source: %s. Valid options are: sysfs, proc, cri", source)
	}
}

func runCRIList() {
	// Check root privileges for CRI access
	if os.Geteuid() != 0 {
		log.Fatalf("CRI discovery requires root privileges")
	}

	discoverer := discover.New(verboseFlag)
	containers, err := discoverer.ListContainers()
	if err != nil {
		log.Fatalf("Failed to list containers via CRI: %v", err)
	}

	if len(containers) == 0 {
		fmt.Println("No containers found via CRI")
		return
	}

	if wideFlag {
		printCRIWideView(containers)
	} else {
		printCRIDefaultView(containers)
	}
	
	fmt.Printf("\nFound %d containers via CRI\n", len(containers))
}

func runTraditionalList(sourceType string) {
	var pairs []extractor.PodContainerPair
	
	if sourceType == "proc" {
		pairs = extractor.ExtractFromProcCgroup()
	} else {
		pairs = extractor.ExtractFromSysfs()
	}
	
	utils.PrintPairs(fmt.Sprintf("Scan containers from %s", sourceType), pairs)
}

func printCRIDefaultView(containers []*discover.Container) {
	fmt.Printf("%-8s %-25s %-25s %-15s\n",
		"PID", "POD", "CONTAINER", "NAMESPACE")
	fmt.Printf("%-8s %-25s %-25s %-15s\n",
		"---", "---", "---------", "---------")
		
	for _, c := range containers {
		podName := getDisplayValue(c.PodName, "N/A")
		containerName := getDisplayValue(c.ContainerName, "N/A")
		namespace := getDisplayValue(c.Namespace, "N/A")
		
		fmt.Printf("%-8d %-25s %-25s %-15s\n",
			c.PID,
			maybeTrunc(podName, 25),
			maybeTrunc(containerName, 25),
			maybeTrunc(namespace, 15),
		)
	}
}

func printCRIWideView(containers []*discover.Container) {
	fmt.Printf("%-8s %-20s %-20s %-15s %-15s %-15s %-20s %-10s\n",
		"PID", "POD", "CONTAINER", "NAMESPACE", "POD_ID", "CONTAINER_ID", "IMAGE_ID", "RUNTIME")
	fmt.Printf("%-8s %-20s %-20s %-15s %-15s %-15s %-20s %-10s\n",
		"---", "---", "---------", "---------", "------", "------------", "--------", "-------")
		
	for _, c := range containers {
		podName := getDisplayValue(c.PodName, "N/A")
		containerName := getDisplayValue(c.ContainerName, "N/A")
		namespace := getDisplayValue(c.Namespace, "N/A")
		runtime := getDisplayValue(c.Runtime, "unknown")
		podID := short(c.PodID, 12)
		containerID := short(c.ContainerID, 12)
		imageID := short(c.ImageID, 18)
		
		fmt.Printf("%-8d %-20s %-20s %-15s %-15s %-15s %-20s %-10s\n",
			c.PID,
			maybeTrunc(podName, 20),
			maybeTrunc(containerName, 20),
			maybeTrunc(namespace, 15),
			maybeTrunc(podID, 15),
			maybeTrunc(containerID, 15),
			maybeTrunc(imageID, 20),
			maybeTrunc(runtime, 10),
		)
	}
}

// Helper functions
func getDisplayValue(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func short(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}

func maybeTrunc(s string, width int) string {
	if noTrunc || width <= 0 || len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}