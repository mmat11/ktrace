package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/cilium/ebpf/rlimit"

	"github.com/mmat11/ktrace/tracer"
)

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	c := new(tracer.Config)
	flag.Func("filter", "Function filter. Supports regex.", func(s string) error {
		re, err := regexp.Compile(s)
		if err != nil {
			return fmt.Errorf("invalid filter: %w", err)
		}
		c.Filter = re
		return nil
	})
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	t, err := tracer.New(c)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer t.Close()

	go t.Record()

	<-stop
}
