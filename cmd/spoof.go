// cmd/spoof.go
package cmd

import (
	"github.com/spf13/cobra"
	"spooffe/spiffe"
	"spooffe/utils"
)

var podUID string
var containerID string

var spoofCmd = &cobra.Command{
	Use:   "spoof",
	Short: "Spoof a cgroup manually",
	Run: func(cmd *cobra.Command, args []string) {
		if podUID == "" || containerID == "" {
			utils.Log("--pod and --container must be provided", nil, "error")
			return
		}
		if _, err := spiffe.SpoofCgroup(podUID, containerID); err != nil {
			utils.Log("Failed to spoof cgroup", err, "error")
			return
		}
		utils.Log("Cgroup spoofed successfully", nil, "success")
	},
}

func init() {
	rootCmd.AddCommand(spoofCmd)
	spoofCmd.Flags().StringVar(&podUID, "pod", "", "Pod UID")
	spoofCmd.Flags().StringVar(&containerID, "container", "", "Container ID")
}
