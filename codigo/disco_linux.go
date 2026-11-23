package main

import "syscall"

// discoUso: total y usado del disco (bytes).
func discoUso(ruta string) (total, usado uint64) {
	var st syscall.Statfs_t
	if syscall.Statfs(ruta, &st) == nil {
		total = st.Blocks * uint64(st.Bsize)
		usado = (st.Blocks - st.Bavail) * uint64(st.Bsize)
	}
	return
}
