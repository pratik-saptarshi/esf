package podman

import "fmt"

// VetProbeScratch is a deliberate go vet failure for CI gate testing only.
// It is never merged.
func VetProbeScratch() string {
	return fmt.Sprintf("%d", "not-a-number")
}
