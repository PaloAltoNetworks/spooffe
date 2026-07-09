// cmd/version.go
package cmd

import (
	"github.com/spf13/cobra"
	"fmt"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(cmd *cobra.Command, args []string) {
		//utils.Log("spooffe v0.1.0", nil, "title")
		printLogo()
	},
}

const logo = `          __  __     
                       / _|/ _|    
 ___ _ __   ___   ___ | |_| |_ ___ 
/ __| '_ \ / _ \ / _ \|  _|  _/ _ \
\__ \ |_) | (_) | (_) | | | ||  __/
|___/ .__/ \___/ \___/|_| |_| \___|
    | |                            
    |_|                            
   SPIFFE SVID Extractor by cgroup Spoofing

	Author: Eviatar Gerzi
	Company: CyberArk
	Version: v0.1.0
	GitHub: https://github.com/cyberark/spooffe
`

func printLogo() {
	fmt.Println(logo)
}


func init() {
	rootCmd.AddCommand(versionCmd)
}
