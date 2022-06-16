package tracer

import (
	"bufio"
	"os"
	"strings"
)

func funcs() ([]string, error) {
	syms := make([]string, 0)

	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := scanner.Text()
		ll := strings.Split(l, " ")
		if len(ll) > 1 {
			continue
		}
		if _, ok := invalid[ll[0]]; ok {
			continue
		}
		syms = append(syms, ll[0])
	}

	return syms, nil
}

var invalid = map[string]struct{}{
	"perf_event_nmi_handler":           {},
	"perf_ibs_nmi_handler":             {},
	"do_int3":                          {},
	"do_trap":                          {},
	"dummy_handler":                    {},
	"oops_end":                         {},
	"oops_begin":                       {},
	"__die_body":                       {},
	"nmi_handle":                       {},
	"unknown_nmi_error":                {},
	"pci_serr_error":                   {},
	"io_check_error":                   {},
	"nmi_cpu_backtrace_handler":        {},
	"arch_rethook_fixup_return":        {},
	"arch_rethook_prepare":             {},
	"arch_rethook_trampoline_callback": {},
	"synthesize_reljump":               {},
	"synthesize_relcall":               {},
	"kprobe_emulate_ifmodifiers":       {},
	"kprobe_emulate_ret":               {},
	"kprobe_emulate_call":              {},
	"kprobe_emulate_jmp":               {},
	"kprobe_emulate_jcc":               {},
	"kprobe_emulate_loop":              {},
	"resume_singlestep":                {},
	"kprobe_emulate_call_indirect":     {},
	"kprobe_emulate_jmp_indirect":      {},
	"kprobe_post_process":              {},
	"setup_singlestep":                 {},
	"reenter_kprobe":                   {},
	"kprobe_int3_handler":              {},
	"kprobe_fault_handler":             {},
	"setup_detour_execution":           {},
	"optimized_callback":               {},
	"kprobe_ftrace_handler":            {},
	"kgdb_roundup_cpus":                {},
	"kgdb_skipexception":               {},
	"kgdb_arch_pc":                     {},
	"kgdb_arch_set_breakpoint":         {},
	"kgdb_arch_remove_breakpoint":      {},
	"spurious_kernel_fault":            {},
	"do_kern_addr_fault":               {},
	"notifier_call_chain":              {},
	"atomic_notifier_call_chain":       {},
	"preempt_count_sub":                {},
	"preempt_count_add":                {},
	"get_kprobe":                       {},
	"kprobe_exceptions_notify":         {},
	"opt_pre_handler":                  {},
	"aggr_pre_handler":                 {},
	"aggr_post_handler":                {},
	"pre_handler_kretprobe":            {},
	"kprobes_inc_nmissed_count":        {},
	"kretprobe_rethook_handler":        {},
	"kgdb_io_ready":                    {},
	"dbg_deactivate_sw_breakpoints":    {},
	"dbg_touch_watchdogs":              {},
	"kgdb_flush_swbreak_addr":          {},
	"dbg_activate_sw_breakpoints":      {},
	"kgdb_cpu_enter":                   {},
	"kgdb_nmicallback":                 {},
	"kgdb_call_nmi_hook":               {},
	"kgdb_nmicallin":                   {},
	"kgdb_reenter_check":               {},
	"kgdb_handle_exception":            {},
	"context_tracking_exit.part.0":     {},
	"context_tracking_exit":            {},
	"context_tracking_enter.part.0":    {},
	"context_tracking_enter":           {},
	"context_tracking_user_exit":       {},
	"context_tracking_user_enter":      {},
	"t_next":                           {},
	"t_stop":                           {},
	"t_start":                          {},
	"may_create":                       {},
	"chacha_permute":                   {},
	"override_function_with_return":    {},
	"mem32_serial_out":                 {},
	"mem32_serial_in":                  {},
	"io_serial_in":                     {},
	"io_serial_out":                    {},
	"__die_header":                     {},
	"__die":                            {},
	"dump_kprobe":                      {},
}
