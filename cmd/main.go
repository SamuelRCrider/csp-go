package main

import (
	"fmt"
	"os"

	"github.com/SamuelRCrider/csp-go/core"
)

func main() {
	input := "My email is jane.doe@example.com and the project codename is Zeus."

	policy, err := core.LoadPolicy("config/default_policy.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading policy: %v\n", err)
		os.Exit(1)
	}

	matches := core.ScanText(input, policy)

	fmt.Println("Matches Found:")
	for _, match := range matches {
		fmt.Printf(" - %s (%s): \"%s\" at [%d:%d]\n",
			match.Type, match.Action, match.Value, match.StartIndex, match.EndIndex)
	}

	result := core.ApplyRedactions(input, matches)

	fmt.Println("\nRedacted Output:")
	fmt.Println(result)
}
