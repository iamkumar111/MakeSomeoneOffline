//go:build !windows && !darwin

package adapters

// RegisterPlatformAdapters is a no-op outside Windows.
func RegisterPlatformAdapters(_ *AdapterRegistry) {}
