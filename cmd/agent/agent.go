// cmd/agent/agent.go
package agent

import (
	"github.com/spf13/cobra"
	"spooffe/cmd/agent/delegatedidentity"
)

// NewAgentCmd returns the root "agent" command and attaches its subcommands.

func NewAgentCmd() *cobra.Command {
	agentCmd := &cobra.Command{
		Use:   "agent",
		Short: "Interact with SPIRE agent APIs",
	}

	agentCmd.PersistentFlags().StringVarP(&adminSocketPath, "socket", "s", "unix:///tmp/spire/sockets/admin.sock", "Path to SPIRE admin socket")
	agentCmd.AddCommand(debugCmd)
	agentCmd.AddCommand(delegatedidentity.NewDelegateCmd())	
	agentCmd.AddCommand(newFetchX509Cmd()) 
	//agentCmd.AddCommand(newAttestPsatCmd()) 
	agentCmd.AddCommand(NewAttestCmd()) 
	

	return agentCmd
}