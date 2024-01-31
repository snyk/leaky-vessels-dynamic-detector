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
package detector

import (
	"ebpf-detector/internal/symlink"
	"ebpf-detector/internal/unlink"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

type buildkitExecutionEvents struct {
	symlinkEvents []*symlink.Event
	unlinkEvents  []*unlink.Event
}

var (
	cacheLock = &sync.Mutex{}
	eventsMap = cache.New(time.Minute, 10*time.Second)
)

func cacheSymlinkEvent(buildkitExecId string, event *symlink.Event) buildkitExecutionEvents {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	events := initCacheForExecutionId(buildkitExecId)
	events.symlinkEvents = append(events.symlinkEvents, event)
	executionEvents, _ := eventsMap.Get(buildkitExecId)
	return *executionEvents.(*buildkitExecutionEvents)
}

func cacheUnlinkEvent(buildkitExecId string, event *unlink.Event) buildkitExecutionEvents {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	events := initCacheForExecutionId(buildkitExecId)
	events.unlinkEvents = append(events.unlinkEvents, event)
	executionEvents, _ := eventsMap.Get(buildkitExecId)
	return *executionEvents.(*buildkitExecutionEvents)
}

func initCacheForExecutionId(buildkitExecId string) *buildkitExecutionEvents {
	var events *buildkitExecutionEvents
	if cachedEvents, exists := eventsMap.Get(buildkitExecId); exists {
		events = cachedEvents.(*buildkitExecutionEvents)
	} else {
		events = &buildkitExecutionEvents{}
		eventsMap.Set(buildkitExecId, events, cache.DefaultExpiration)
	}

	return events
}
