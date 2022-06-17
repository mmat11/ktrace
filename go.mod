module github.com/mmat11/ktrace

go 1.18

require (
	github.com/cilium/ebpf v0.9.0
	github.com/rs/zerolog v1.27.0
)

require (
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	golang.org/x/sys v0.0.0-20210927094055-39ccf1dd6fa6 // indirect
)

replace github.com/cilium/ebpf => ../ebpf
