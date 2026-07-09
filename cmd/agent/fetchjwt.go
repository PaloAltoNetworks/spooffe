package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spf13/cobra"
)

func newFetchJWTCmd() *cobra.Command {
	var (
		socketURI string
		audience  string
		outPath   string
		timeout   time.Duration
	)

	cmd := &cobra.Command{
		Use:   "jwt",
		Short: "Fetch a JWT-SVID via the Workload API (spire-agent socket)",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			client, err := workloadapi.New(ctx,
				workloadapi.WithAddr(socketURI))
			if err != nil {
				return fmt.Errorf("connect workload API: %w", err)
			}
			defer client.Close()

			svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{
				Audience: audience,
			})
			if err != nil {
				return fmt.Errorf("fetch JWT-SVID: %w", err)
			}

			fmt.Println("JWT-SVID fetched successfully")
			fmt.Println("  SPIFFE ID:", svid.ID.String())
			fmt.Println("  Audience :", svid.Audience)
			fmt.Println("  Expires  :", svid.Expiry.UTC().Format(time.RFC3339))

			if outPath != "" {
				if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(outPath, []byte(svid.Marshal()), 0o600); err != nil {
					return err
				}
				fmt.Println("  Wrote token to:", outPath)
			} else {
				fmt.Println("  Token    :", svid.Marshal())
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&socketURI, "socket", "unix:///run/spire/sockets/agent.sock", "Workload API socket URI")
	cmd.Flags().StringVar(&audience, "audience", "", "Audience for the JWT-SVID (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "Write JWT token to file (0600)")
	cmd.Flags().DurationVar(&timeout, "timeout", 15*time.Second, "Timeout for Workload API calls")

	_ = cmd.MarkFlagRequired("audience")

	return cmd
}
