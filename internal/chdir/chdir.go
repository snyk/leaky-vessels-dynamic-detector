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
package chdir

import (
	"ebpf-detector/internal/logger"
	"ebpf-detector/internal/utils"
	"errors"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf chdir.c -- -I../../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -type event bpf chdir.c -- -I../../headers

type Event struct {
	Pid  uint32
	Path string
}

type EventCallback func(*Event)

func Listen(callback EventCallback) {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		logger.Error(err, "Failed loading chdir bpf objects")
		return
	}
	defer objs.Close()

	chdir, err := link.Tracepoint("syscalls", "sys_enter_chdir", objs.TraceChdir, nil)
	if err != nil {
		logger.Error(err, "Failed setting chdir tracepoint")
		return
	} else {
		defer chdir.Close()
	}

	logger.Info("Listening on chdir events")
	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		logger.Error(err, "Failed reading chdir events map")
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
		path := utils.ConvertCString(bpfEvent.Path[:])
		callback(&Event{bpfEvent.Pid, path})
	}
}
