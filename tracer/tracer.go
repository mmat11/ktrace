package tracer

import (
	"errors"
	"os"
	"regexp"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/rs/zerolog"
)

type Config struct {
	Filter *regexp.Regexp
}

type Tracer struct {
	logger    zerolog.Logger
	ringbuf   *ringbuf.Reader
	kml, krml link.Link
	// cookie->sym mapping
	refs map[uint64]string
}

func (t *Tracer) Close() {
	t.ringbuf.Close()
	t.kml.Close()
	t.krml.Close()
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf ../bpf/ktrace.c

func New(c *Config, logger zerolog.Logger) (*Tracer, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, err
	}
	if err := spec.RewriteConstants(map[string]interface{}{"self": uint32(os.Getpid())}); err != nil {
		return nil, err
	}

	objs := bpfObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, err
	}
	defer objs.Close()

	rb, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		return nil, err
	}

	t := &Tracer{
		logger:  logger,
		ringbuf: rb,
		refs:    make(map[uint64]string, 0),
	}

	syms, err := funcs()
	if err != nil {
		return nil, err
	}

	opts := link.KprobeMultiOptions{}
	opts.Symbols = make([]string, 0)
	opts.Cookies = make([]uint64, 0)

	if c.Filter == nil {
		logger.Warn().Msg("recording without filter could crash the system!")
	}

	for sym, cookie := range syms {
		if c.Filter != nil && !c.Filter.MatchString(sym) {
			continue
		}

		opts.Symbols = append(opts.Symbols, sym)
		opts.Cookies = append(opts.Cookies, cookie)
		t.refs[cookie] = sym
	}

	logger.Info().Int("symbols", len(opts.Symbols)).Send()

	kml, err := link.KprobeMulti(objs.KprobeGeneric, opts)
	if err != nil {
		return nil, err
	}
	t.kml = kml

	krml, err := link.KretprobeMulti(objs.KretprobeGeneric, opts)
	if err != nil {
		return nil, err
	}
	t.krml = krml

	return t, nil
}

func (t *Tracer) Record() {
	ev := new(Event)

	for {
		record, err := t.ringbuf.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			t.logger.Err(err).Send()
			continue
		}

		if err := ev.UnmarshalBinary(t, record.RawSample); err != nil {
			t.logger.Err(err).Send()
			return
		}

		t.logger.Log().RawJSON("event", ev.Raw()).Send()
	}
}
