#include "vmlinux.h"
#include "bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 65536 * 1024);
} ringbuf SEC(".maps");

enum ev_kind {
    EV_KIND_ENTER,
    EV_KIND_EXIT,
};

struct event {
    enum ev_kind kind;
    u32 pid;
    u64 cookie;
    u64 usec;
    s32 retval;
} __attribute__((packed));

static int trace_generic(struct pt_regs *ctx, enum ev_kind kind, int ret) {
    struct event *ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
    if (!ev) {
        bpf_printk("ringbuf reserve failed");
        return 0;
    }

    ev->kind = kind;
    ev->pid = bpf_get_current_pid_tgid();
    ev->cookie = bpf_get_attach_cookie(ctx);
    ev->usec = bpf_ktime_get_boot_ns() / 1000;
    ev->retval = ret;

    bpf_ringbuf_submit(ev, 0);

    return 0;
}

SEC("kprobe.multi/generic")
int kprobe_generic(struct pt_regs *ctx) {
    return trace_generic(ctx, EV_KIND_ENTER, 0);
}

SEC("kretprobe.multi/generic")
int kretprobe_generic(struct pt_regs *ctx) {
    return trace_generic(ctx, EV_KIND_EXIT, ctx->ax);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
