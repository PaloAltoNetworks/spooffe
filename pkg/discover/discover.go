package discover

import (
	"log"
	"sort"
)

type Discoverer struct {
	verbose   bool
	providers []Provider
}

func New(verbose bool) *Discoverer {
	d := &Discoverer{
		verbose: verbose,
	}
	
	// Register providers in order of preference
	d.providers = []Provider{
		//NewProcScanProvider(verbose),
		// NewDockerProvider(verbose),
		//NewContainerdProvider(verbose),
		NewCRIProvider(verbose),
		//NewProcScanProvider(verbose),
	}
	
	return d
}

func (d *Discoverer) ListContainers() ([]*Container, error) {
	var allContainers []*Container
	seen := make(map[int]bool)
	
	for _, provider := range d.providers {
		if !provider.IsAvailable() {
			if d.verbose {
				log.Printf("Provider %s not available, skipping", provider.Name())
			}
			continue
		}
		
		if d.verbose {
			log.Printf("Discovering containers using %s provider", provider.Name())
		}
		
		containers, err := provider.Discover()
		if err != nil {
			if d.verbose {
				log.Printf("Provider %s failed: %v", provider.Name(), err)
			}
			continue
		}
		
		// Deduplicate by PID
		for _, container := range containers {
			if !seen[container.PID] {
				allContainers = append(allContainers, container)
				seen[container.PID] = true
			}
		}
		
		if d.verbose {
			log.Printf("Provider %s found %d containers", provider.Name(), len(containers))
		}
	}
	
	// Sort by PID
	sort.Slice(allContainers, func(i, j int) bool {
		return allContainers[i].PID < allContainers[j].PID
	})
	
	return allContainers, nil
}