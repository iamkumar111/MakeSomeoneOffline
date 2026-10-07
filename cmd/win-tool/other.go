//go:build !windows

package main

// Non-Windows builds only expose usage; runtime behavior is Windows-only.
func runDoctor()         {}
func runProbe()          {}
func runScan(_ []string) {}
func runCut(_ []string)  {}
func runHeal(_ []string) {}
