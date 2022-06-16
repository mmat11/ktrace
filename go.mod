module github.com/mmat11/ktrace

go 1.17

require github.com/cilium/ebpf v0.8.2-0.20220404151855-0d439865ca15

require golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34 // indirect

replace github.com/cilium/ebpf => ../ebpf
