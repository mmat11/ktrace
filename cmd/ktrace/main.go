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
	"github.com/rs/zerolog"

	"github.com/mmat11/ktrace/tracer"
)

func main() {
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger()

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
		logger.Fatal().Err(err).Send()
	}

	t, err := tracer.New(c, logger)
	if err != nil {
		logger.Fatal().Err(err).Send()
	}
	defer t.Close()

	go t.Record()

	<-stop
}
