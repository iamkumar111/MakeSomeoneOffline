package adapters

import (
	"github.com/open-netcut/open-netcut/pkg/models"
	"testing"
)

func TestNFTRejectsCommandAndRuleInjection(t *testing.T) {
	for _, target := range []string{"192.168.1.24; echo owned", "192.168.1.24\nflush ruleset", "$(whoami)", "192.168.1.24 drop; flush ruleset"} {
		if err := validateNFTTarget("open_netcut", &models.Enforcement{TargetIP: target}); err == nil {
			t.Fatalf("accepted %q", target)
		}
	}
	if err := validateNFTTarget("unsafe;command", &models.Enforcement{TargetIP: "192.168.1.24"}); err == nil {
		t.Fatal("accepted invalid table")
	}
	if err := validateNFTTarget("open_netcut", &models.Enforcement{TargetMAC: "02:00:00:00:00:24;command"}); err == nil {
		t.Fatal("accepted invalid MAC")
	}
	if err := validateNFTTarget("open_netcut", &models.Enforcement{TargetIP: "2001:db8::24"}); err != nil {
		t.Fatal(err)
	}
}

func TestNFTRemovalCannotMatchAnotherIPPrefix(t *testing.T) {
	line := "ip saddr 192.168.1.240 drop # handle 7"
	if nftTokenMatch(line, "192.168.1.24") {
		t.Fatal("removal matched a different target")
	}
	if !nftTokenMatch(line, "192.168.1.240") {
		t.Fatal("exact target not matched")
	}
	if isNFTHandle("7; flush ruleset") {
		t.Fatal("invalid kernel handle accepted")
	}
}
