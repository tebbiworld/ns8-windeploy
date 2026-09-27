// Check that every "pattern" in the action schemas compiles with Go regexp
// (RE2), the engine the NS8 agent validates with. Python accepts escapes
// like \u0000 that RE2 rejects, which aborts the action before it starts.
// Usage: go run tests/schema/check_patterns.go imageroot/actions/*/validate-*.json

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

func walk(v interface{}, file string, bad *int) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, x := range t {
			if k == "pattern" {
				if s, ok := x.(string); ok {
					if _, err := regexp.Compile(s); err != nil {
						fmt.Printf("%s: %q: %v\n", file, s, err)
						*bad++
					}
				}
			}
			walk(x, file, bad)
		}
	case []interface{}:
		for _, x := range t {
			walk(x, file, bad)
		}
	}
}

func main() {
	bad := 0
	for _, f := range os.Args[1:] {
		b, _ := os.ReadFile(f)
		var v interface{}
		if err := json.Unmarshal(b, &v); err != nil {
			fmt.Println(f, err)
			bad++
			continue
		}
		walk(v, f, &bad)
	}
	fmt.Printf("%d schema file(s), %d bad pattern(s)\n", len(os.Args)-1, bad)
	if bad > 0 {
		os.Exit(1)
	}
}
