//go:build darwin

package adapters

func RegisterPlatformAdapters(r *AdapterRegistry) {
	r.Register(newMacOSSideHostAdapter(macOSDependencies{check: checkMacBPF, resolve: resolveMacPlan, open: openMacBPF}))
}
