package protocol

import (
	"errors"
	"fmt"
	"sync"
)

const WindowSize = 64
const maxRetiredEpochs = 4096

var (
	ErrReplayed      = errors.New("replay: packet duplikat")
	ErrTooOld        = errors.New("replay: counter terlalu lama")
	ErrRetiredEpoch  = errors.New("replay: epoch sudah tidak berlaku")
	ErrTooManyEpochs = errors.New("replay: terlalu banyak pergantian epoch")
)

type Window struct {
	mu      sync.Mutex
	started bool
	epoch   uint32
	last    uint64
	bitmap  uint64
	retired map[uint32]struct{}

	accepted     uint64
	rejected     uint64
	epochChanges uint64
}

func NewWindow() *Window {
	return &Window{retired: make(map[uint32]struct{})}
}

func (w *Window) Check(epoch uint32, counter uint64) error {
	if counter == 0 {
		return ErrBadCounter
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, dead := w.retired[epoch]; dead {
		w.rejected++
		return fmt.Errorf("%w: epoch=%08x", ErrRetiredEpoch, epoch)
	}

	switch {
	case !w.started:
		w.started = true
		w.epoch = epoch
		w.last = counter
		w.bitmap = 1
		w.accepted++
		return nil

	case epoch != w.epoch:
		if len(w.retired) >= maxRetiredEpochs {
			w.rejected++
			return fmt.Errorf("%w: %d epoch tercatat", ErrTooManyEpochs, len(w.retired))
		}
		w.retired[w.epoch] = struct{}{}
		w.epoch = epoch
		w.last = counter
		w.bitmap = 1
		w.epochChanges++
		w.accepted++
		return nil
	}

	switch {
	case counter > w.last:
		shift := counter - w.last
		if shift >= WindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.last = counter
		w.accepted++
		return nil

	case counter == w.last:
		w.rejected++
		return fmt.Errorf("%w: counter=%d", ErrReplayed, counter)

	default:
		diff := w.last - counter
		if diff >= WindowSize {
			w.rejected++
			return fmt.Errorf("%w: counter=%d, terakhir=%d", ErrTooOld, counter, w.last)
		}
		mask := uint64(1) << diff
		if w.bitmap&mask != 0 {
			w.rejected++
			return fmt.Errorf("%w: counter=%d", ErrReplayed, counter)
		}
		w.bitmap |= mask
		w.accepted++
		return nil
	}
}

func (w *Window) Stats() (accepted, rejected, epochChanges uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.accepted, w.rejected, w.epochChanges
}

func (w *Window) Epoch() (uint32, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.epoch, w.started
}
