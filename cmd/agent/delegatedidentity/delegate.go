// agent/delegate.go
package delegatedidentity

import (
	"github.com/spf13/cobra"
)

func NewDelegateCmd() *cobra.Command {
	delegateCmd := &cobra.Command{
        Use:   "delegate",
        Short: "Call delegated identity APIs",
    }
	delegateCmd.AddCommand(fetchJWTCmd)
	
	return delegateCmd
}

