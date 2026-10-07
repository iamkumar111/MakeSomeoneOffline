package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/open-netcut/open-netcut/pkg/adapters"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "probe" {
		fmt.Fprintln(os.Stderr, "Usage: mac-tool probe [-target LAN_IPV4] (sends no packets)")
		os.Exit(2)
	}
	flags := flag.NewFlagSet("probe", flag.ExitOnError)
	target := flags.String("target", "", "Optional target IP; defaults to gateway")
	flags.Parse(os.Args[2:])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := adapters.MacOSProbe(ctx, *target)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if encodeErr := encoder.Encode(result); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}
