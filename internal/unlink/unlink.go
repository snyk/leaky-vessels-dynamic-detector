/*
 * © 2024 Snyk Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package unlink

import (
	"ebpf-detector/internal/logger"
	"ebpf-detector/internal/utils"
	"errors"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf unlink.c -- -I../../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -type event bpf unlink.c -- -I../../headers

type Event struct {
	Pid             uint32
	Path            string
	TimestampMicros uint64
}

type ExploitDetectionHandler func(*Event)

func Listen(handler ExploitDetectionHandler) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		logger.Error(err, "Failed loading unlink bpf objects")
		return
	}
	defer objs.Close()

	tracepointSet := false
	if runtime.GOARCH != "arm64" {
		unlink, err := link.Tracepoint("syscalls", "sys_enter_unlink", objs.TraceUnlink, nil)
		if err != nil {
			logger.Error(err, "Failed setting unlink tracepoint")
		} else {
			tracepointSet = true
			defer unlink.Close()
		}
	}

	unlinkat, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.TraceUnlinkat, nil)
	if err != nil {
		logger.Error(err, "Failed setting unlinkat tracepoint")
	} else {
		tracepointSet = true
		defer unlinkat.Close()
	}

	if !tracepointSet {
		return
	}

	readOpenEvents(objs.Events, handler)
}

func readOpenEvents(events *ebpf.Map, handler ExploitDetectionHandler) {
	logger.Info("Listening on unlink events")
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		logger.Error(err, "Failed reading unlink events map")
		return
	}

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			return
		}

		bpfEvent := (*bpfEvent)(unsafe.Pointer(&record.RawSample[0]))
		pathname := utils.ConvertCString(bpfEvent.Pathname[:])
		timestampMicros := bpfEvent.Timestamp / 1000 // eBPF timestamp is in nanos
		handler(&Event{bpfEvent.Pid, pathname, timestampMicros})
	}
}
