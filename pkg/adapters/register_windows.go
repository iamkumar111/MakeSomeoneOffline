//go:build windows

package adapters

// RegisterPlatformAdapters exposes the Windows enforcement scaffold.
func RegisterPlatformAdapters(r *AdapterRegistry) {
	r.Register(NewWindowsSideHostAdapter())
}
