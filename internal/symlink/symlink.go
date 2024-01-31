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
package symlink

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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf symlink.c -- -I../../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -type event bpf symlink.c -- -I../../headers

type Event struct {
	Pid             uint32
	Target          string
	Linkpath        string
	TimestampMicros uint64
}

type ExploitDetectionHandler func(*Event)

func Listen(handler ExploitDetectionHandler) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		logger.Error(err, "Failed loading symlink bpf objects")
		return
	}
	defer objs.Close()

	tracepointSet := false
	if runtime.GOARCH != "arm64" {
		symlink, err := link.Tracepoint("syscalls", "sys_enter_symlink", objs.TraceSymlink, nil)
		if err != nil {
			logger.Error(err, "Failed setting symlink tracepoint")
		} else {
			tracepointSet = true
			defer symlink.Close()
		}
	}

	symlinkat, err := link.Tracepoint("syscalls", "sys_enter_symlinkat", objs.TraceSymlinkat, nil)
	if err != nil {
		logger.Error(err, "Failed setting symlinkat tracepoint")
	} else {
		tracepointSet = true
		defer symlinkat.Close()
	}

	if !tracepointSet {
		return
	}

	readOpenEvents(objs.Events, handler)
}

func readOpenEvents(events *ebpf.Map, handler ExploitDetectionHandler) {
	logger.Info("Listening on symlink events")
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		logger.Error(err, "Failed reading symlink events map")
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
		newName := utils.ConvertCString(bpfEvent.Newname[:])
		oldName := utils.ConvertCString(bpfEvent.Oldname[:])
		timestampMicros := bpfEvent.Timestamp / 1000 // eBPF timestamp is in nanos
		handler(&Event{bpfEvent.Pid, oldName, newName, timestampMicros})
	}
}
