package agent

import (
	"context"
	"fmt"
	"log"
	"time"
	
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/debug/v1"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var debugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Call the SPIRE Agent's Debug GetInfo API",
	Run: func(cmd *cobra.Command, args []string) {
		callDebugInfo()
	},
}

// func NewAgentCmd() *cobra.Command {
// 	agentCmd := &cobra.Command{
// 		Use:   "agent",
// 		Short: "Interact with SPIRE agent APIs",
// 	}

// 	agentCmd.PersistentFlags().StringVarP(&adminSocketPath, "socket", "s", "unix:///tmp/spire/sockets/admin.sock", "Path to SPIRE admin socket")
// 	agentCmd.AddCommand(debugCmd)
// 	agentCmd.AddCommand(delegatedidentity.NewDelegateAPICmd())	

// 	return agentCmd
// }

var adminSocketPath string

func init() {

	//debugCmd.Flags().StringVarP(&adminSocketPath, "socket", "s", "unix:///tmp/spire/sockets/admin.sock", "Path to SPIRE admin socket")
	//rootCmd.AddCommand(debugCmd)
}

func callDebugInfo() {
	conn, err := grpc.DialContext(
		context.Background(),
		adminSocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to connect to SPIRE agent: %v", err)
	}
	defer conn.Close()

	client := debugv1.NewDebugClient(conn)

	resp, err := client.GetInfo(context.Background(), &debugv1.GetInfoRequest{})
	if err != nil {
		log.Fatalf("GetInfo call failed: %v", err)
	}

	fmt.Printf("Last Sync Success   : %s\n", time.Unix(resp.LastSyncSuccess, 0).UTC())
	fmt.Printf("Uptime              : %d seconds\n", resp.Uptime)
	fmt.Printf("SVIDs Count (legacy): %d\n", resp.SvidsCount)
	fmt.Printf("Cached X.509 SVIDs  : %d\n", resp.CachedX509SvidsCount)
	fmt.Printf("Cached JWT SVIDs    : %d\n", resp.CachedJwtSvidsCount)
	fmt.Printf("SVIDStore X.509 SVIDs: %d\n", resp.CachedSvidstoreX509SvidsCount)

	for i, cert := range resp.SvidChain {
		fmt.Printf("\nSVID Cert [%d]:\n", i)
		fmt.Printf("  Subject    : %s\n", cert.Subject)
		if cert.Id != nil {
			fmt.Printf("  SPIFFE ID  : spiffe://%s%s\n", cert.Id.TrustDomain, cert.Id.Path)
		}
		fmt.Printf("  Expires At : %s\n", time.Unix(cert.ExpiresAt, 0).UTC())
	}
}
