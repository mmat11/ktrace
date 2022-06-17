package tracer

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

type EventKind string

const (
	EventKindEnter EventKind = "ENTER"
	EventKindExit  EventKind = "EXIT"
)

type Event struct {
	Kind   EventKind `json:"kind"`
	Symbol string    `json:"symbol"`
	Pid    uint32    `json:"pid"`
	Usec   uint64    `json:"usec"`
	Ret    int32     `json:"ret"`
}

func (e *Event) UnmarshalBinary(t *Tracer, data []byte) error {
	kind := binary.LittleEndian.Uint32(data[0:4])
	switch kind {
	case 0:
		e.Kind = EventKindEnter
	case 1:
		e.Kind = EventKindExit
	}
	e.Pid = binary.LittleEndian.Uint32(data[4:8])
	cookie := binary.LittleEndian.Uint64(data[8:16])
	sym, ok := t.refs[cookie]
	if !ok {
		return fmt.Errorf("symbol for cookie %d not found", cookie)
	}
	e.Symbol = sym
	e.Usec = binary.LittleEndian.Uint64(data[16:24])

	var ret int32
	if err := binary.Read(bytes.NewBuffer(data[24:28]), binary.LittleEndian, &ret); err != nil {
		return err
	}
	e.Ret = ret

	return nil
}

func (e *Event) Raw() []byte {
	b, _ := json.Marshal(e)
	return b
}
