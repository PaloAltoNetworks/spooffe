// cmd/spooffe/server.go
package server

import (
	"github.com/spf13/cobra"
	"time"
)

// CommonConfig holds shared configuration across all server commands
type CommonConfig struct {
	ServerAddress  string  // host:port (NodeIP:NodePort OK)
	TrustDomainStr string
	CACertPath     string
	ClientCertPath string
	ClientKeyPath  string
	Timeout        time.Duration
}

func NewServerCmd() *cobra.Command {
	var commonCfg CommonConfig

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Interact with SPIRE server APIs",
	}

	// Add common flags to the server command
	cmd.PersistentFlags().StringVar(&commonCfg.ServerAddress, "server-address", "localhost:8081", "SPIRE server address (host:port)")
	cmd.PersistentFlags().StringVar(&commonCfg.TrustDomainStr, "trust-domain", "example.org", "SPIFFE trust domain (e.g., example.org)")
	cmd.PersistentFlags().StringVar(&commonCfg.CACertPath, "ca-cert", "", "Path to server CA/bundle (PEM)")
	cmd.PersistentFlags().StringVar(&commonCfg.ClientCertPath, "client-cert", "", "Path to client certificate (agent SVID)")
	cmd.PersistentFlags().StringVar(&commonCfg.ClientKeyPath, "client-key", "", "Path to client private key")
	cmd.PersistentFlags().DurationVar(&commonCfg.Timeout, "timeout", 30*time.Second, "RPC timeout")

	// Add all the server subcommands
	cmd.AddCommand(NewJWTCmd(&commonCfg))
	cmd.AddCommand(NewCollectJWTsCmd(&commonCfg))
	cmd.AddCommand(NewCollectX509Cmd(&commonCfg))
	cmd.AddCommand(NewEntriesCmd(&commonCfg))
	cmd.AddCommand(NewRenewCmd())
	cmd.AddCommand(NewBundleCmd())

	return cmd
}