package utils

import (
	"fmt"
	"strings"
	"spooffe/extractor"
)

func Colorize(text, level string) string {
	switch level {
	case "success", "info":
		return fmt.Sprintf("%s%s%s", Green, text, Reset)
	case "error":
		return fmt.Sprintf("%s%s%s", Red, text, Reset)
	case "warn":
		return fmt.Sprintf("%s%s%s", Yellow, text, Reset)
	default:
		return text
	}
}

func PrintPairs(header string, pairs []extractor.PodContainerPair) {
	podMap := make(map[string][]string)
	for _, p := range pairs {
		podMap[p.PodUID] = append(podMap[p.PodUID], p.ContainerID)
	}

	fmt.Printf("\n%s%s%s\n", Cyan, Bold, header)
	fmt.Printf("%s%-40s | %-64s%s\n", Bold, "Pod UID", "Container ID", Reset)
	fmt.Println(strings.Repeat("-", 107))

	for podUID, containerIDs := range podMap {
		for _, containerID := range containerIDs {
			fmt.Printf("%s%-40s%s | %s%-64s%s\n",
				Yellow, podUID, Reset,
				Green, containerID, Reset,
			)
		}
	}

	fmt.Println("")
	Log(fmt.Sprintf("Found %s%d%s pod/container pairs%s\n\n", Reset,len(pairs), Green, Reset), nil, "info")
	//fmt.Printf("\n%s[*] Found %d pod/container pairs%s\n\n", Bold, len(pairs), Reset)
}
