package tracer

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Config struct {
	Filter *regexp.Regexp
}

type Tracer struct {
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

func New(c *Config) (*Tracer, error) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, err
	}
	defer objs.Close()

	rb, err := ringbuf.NewReader(objs.Ringbuf)
	if err != nil {
		return nil, err
	}

	t := &Tracer{
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
		fmt.Printf("warning: no func filter will most likely KO your pc!\n")
	}

	for i, sym := range syms {
		if c.Filter != nil && !c.Filter.MatchString(sym) {
			continue
		}

		cookie := uint64(i)
		opts.Symbols = append(opts.Symbols, sym)
		opts.Cookies = append(opts.Cookies, cookie)
		t.refs[cookie] = sym
	}

	kml, err := link.KprobeMulti(objs.KprobeGeneric, &opts)
	if err != nil {
		return nil, err
	}
	t.kml = kml

	krml, err := link.KretprobeMulti(objs.KretprobeGeneric, &opts)
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
			fmt.Printf("ringbuf read: %v\n", err)
			continue
		}

		if err := ev.UnmarshalBinary(t, record.RawSample); err != nil {
			fmt.Printf("unmarshal event: %v\n", err)
			return
		}

		fmt.Println(ev.String())
	}
}
