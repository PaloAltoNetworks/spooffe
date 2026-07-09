package delegatedidentity

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	delegatedidentityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"spooffe/utils"
)

var fetchJWTCmd = &cobra.Command{
	Use:   "fetchjwt",
	Short: "Call FetchJWTSVIDs from delegated identity API",
	Run: func(cmd *cobra.Command, args []string) {
		callFetchJWT()
	},
}

var (
	delegateSocketPath string
	audience           string
	workloadPID        int32
	selectors          []string
)

func init() {
	fetchJWTCmd.Flags().StringVarP(&delegateSocketPath, "socket", "s", "unix:///tmp/spire/sockets/admin.sock", "Path to SPIRE delegated admin socket")
	fetchJWTCmd.Flags().StringVarP(&audience, "audience", "a", "example.org", "Audience for the JWT-SVID")
	fetchJWTCmd.Flags().Int32VarP(&workloadPID, "pid", "p", 0, "PID of the workload process")
	fetchJWTCmd.Flags().StringSliceVarP(&selectors, "selectors", "e", nil, "Workload selectors in format 'type:value' (e.g., 'unix:uid:1001,unix:uid:1002')")
}

func parseSelectors(selectorStrings []string) ([]*types.Selector, error) {
	var parsedSelectors []*types.Selector
	
	for _, selectorStr := range selectorStrings {
		parts := strings.SplitN(selectorStr, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid selector format '%s', expected 'type:value'", selectorStr)
		}
		
		parsedSelectors = append(parsedSelectors, &types.Selector{
			Type:  parts[0],
			Value: parts[1],
		})
	}
	
	return parsedSelectors, nil
}

func callFetchJWT() {
	// Validate that either PID or selectors are provided, but not both
	if workloadPID == 0 && len(selectors) == 0 {
		log.Fatal("either workload PID (--pid) or selectors (--selectors) must be specified")
	}
	
	if workloadPID != 0 && len(selectors) > 0 {
		log.Fatal("cannot specify both PID and selectors, choose one method")
	}

	conn, err := grpc.DialContext(
		context.Background(),
		delegateSocketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithTimeout(5*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to connect to SPIRE agent: %v", err)
	}
	defer conn.Close()

	client := delegatedidentityv1.NewDelegatedIdentityClient(conn)
	
	// Build the request based on whether PID or selectors are used
	req := &delegatedidentityv1.FetchJWTSVIDsRequest{
		Audience: []string{audience},
	}
	
	if workloadPID != 0 {
		req.Pid = workloadPID
		fmt.Println(utils.FormatLogLine("Using PID-based identification:", fmt.Sprintf("%d", workloadPID), "info"))
	} else {
		parsedSelectors, err := parseSelectors(selectors)
		if err != nil {
			log.Fatalf("failed to parse selectors: %v", err)
		}
		req.Selectors = parsedSelectors
		fmt.Println(utils.FormatLogLine("Using selector-based identification:", fmt.Sprintf("%v", selectors), "info"))
	}

	resp, err := client.FetchJWTSVIDs(context.Background(), req)
	if err != nil {
		log.Fatalf("FetchJWTSVIDs call failed: %v", err)
	}

	for i, svid := range resp.Svids {
		messageJWTSVID := fmt.Sprintf("JWT-SVID [%d]:", i)
		spiffeId := fmt.Sprintf("spiffe://%s%s", svid.Id.TrustDomain, svid.Id.Path)
		fmt.Println(utils.FormatLogLine(messageJWTSVID, nil, "info"))
		fmt.Println(utils.FormatLogLine("  SPIFFE ID:", spiffeId, "info"))
		fmt.Println(utils.FormatLogLine("  Token:", svid.Token, "info"))
		fmt.Println("")
	}
}