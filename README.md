# ktrace

Ktrace is a small kernel tracing utility built to experiment with eBPF's kprobe_multi link.

To play with it:

```
go run ./cmd/ktrace -filter 'inet|tcp' |jq
{
  "kind": "ENTER",
  "symbol": "tcp_cleanup_rbuf",
  "pid": 11242,
  "usec": 2587100953,
  "ret": 0
}
{
  "kind": "EXIT",
  "symbol": "tcp_cleanup_rbuf",
  "pid": 11242,
  "usec": 2587100957,
  "ret": 0
}
{
  "kind": "EXIT",
  "symbol": "tcp_recvmsg_locked",
  "pid": 11242,
  "usec": 2587100957,
  "ret": -11
}
{
  "kind": "ENTER",
  "symbol": "tcp_release_cb",
  "pid": 11242,
  "usec": 2587100957,
  "ret": 0
}
{
  "kind": "EXIT",
  "symbol": "tcp_release_cb",
  "pid": 11242,
  "usec": 2587100957,
  "ret": -1480971152
}
{
  "kind": "EXIT",
  "symbol": "tcp_recvmsg",
  "pid": 11242,
  "usec": 2587100958,
  "ret": -11
}
{
  "kind": "EXIT",
  "symbol": "inet_recvmsg",
  "pid": 11242,
  "usec": 2587100958,
  "ret": -11
}
```
