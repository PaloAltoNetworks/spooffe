package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"spooffe/cmd/agent"
	"spooffe/cmd/server"
	"spooffe/cmd/list"
	"spooffe/cmd/dump"
	"spooffe/utils"
)

var (
	scanType   string
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "spooffe",
	Short: "SPIFFE SVID extractor and agent utility",
	Long:  `spooffe is a CLI tool to extract SVIDs from SPIRE agents using
cgroup spoofing techniques, interact with agent debug and delegated identity APIs,
list pod/container mappings, and more.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		_ = utils.InitFileLogger()
		fullCmd := "spooffe " + strings.Join(os.Args[1:], " ")
		utils.LogToFile("started — command: " + fullCmd)
		return nil
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		utils.CloseFileLogger()
	},
	Run: func(cmd *cobra.Command, args []string) {
		printLogo()
		fmt.Println("Please specify a subcommand. Use --help for more information.")
		
		// pairs := extractor.ExtractFromProcCgroup()
		// utils.PrintPairs("Scan containers from /proc/<pid>/cgroup", pairs)

		// pairs2 := extractor.ExtractFromSysfs()
		// utils.PrintPairs("Scan containers from /sys/fs/cgroup/kubepods.slice", pairs2)
		
		// for _, pair := range pairs2 {
		// 	if strings.HasPrefix(pair.PodUID, "692") {

		// 		utils.Log("Pod UID:", pair.PodUID, "info")
		// 		utils.Log("Container ID:", pair.ContainerID, "info")
		// 		//dumpSVIDs(pair)
		// 		if _, err := spiffe.SpoofCgroup(pair.PodUID, pair.ContainerID); err != nil {
		// 			utils.Log("Failed to spoof cgroup", err, "error")
		// 		}
		// 		utils.Log("Fetching JWT-SVID for", pair.ContainerID, "info")

		// 		spiffe.FetchAndSaveJWT(pair)
		// 		spiffe.FetchAndSaveX509(pair)

		// 		fmt.Println("\n")
		// 		time.Sleep(1 * time.Second)
		// 	}

		// }
	},
}



// Execute adds all child commands to the root command and sets flags appropriately
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(agent.NewAgentCmd())
	rootCmd.AddCommand(server.NewServerCmd())
	rootCmd.AddCommand(list.NewListCmd())
	rootCmd.AddCommand(dump.NewDumpCmd())
	rootCmd.AddCommand(dump.NewChildDumpCmd())
	//rootCmd.PersistentFlags().StringVarP(&socketPath, "socket", "s", "/run/spire/sockets/agent.sock", "Path to SPIRE agent socket")
	//rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 5, "Timeout in seconds for each fetch operation")
	//rootCmd.PersistentFlags().StringVarP(&scanType, "type", "y", "both", "SVID types to extract: jwt, x509, or both")
}
