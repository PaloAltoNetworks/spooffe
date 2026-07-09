package agent

import "github.com/spf13/cobra"

func newFetchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch SVIDs via the Workload API",
	}

	cmd.AddCommand(newFetchX509Cmd())
	cmd.AddCommand(newFetchJWTCmd())

	return cmd
}
