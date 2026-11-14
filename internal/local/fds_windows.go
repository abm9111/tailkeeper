//go:build windows

package local

// closeInheritedOnExec does nothing on Windows: os/exec gives the child an explicit
// list of the handles it may inherit (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), which holds
// only its standard streams.
func closeInheritedOnExec() {}
