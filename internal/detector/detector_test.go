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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const executionId = "2sqikyu8yefq6v6pm2lnl7z3p"

func TestExecutorFolderRegex(t *testing.T) {
	cmdline := fmt.Sprintf("runc --log /var/lib/docker/buildkit/executor/runc-log.json --log-format json run --bundle /var/lib/docker/buildkit/executor/%s %s", executionId, executionId)
	matches := executorFolderRegex.FindStringSubmatch(cmdline)
	assert.Equal(t, len(matches), 2)
	assert.Equal(t, matches[1], executionId)
}

func TestExecutorRootFsRegex(t *testing.T) {
	unlinkPath := fmt.Sprintf("/var/lib/docker/buildkit/executor/%s/rootfs/tmp/stage/delete_me_proof_of_concept", executionId)
	matches := executorRootFsRegex.FindStringSubmatch(unlinkPath)
	assert.Equal(t, len(matches), 2)
	assert.Equal(t, matches[1], executionId)
}

func TestDetectContainerTeardownDeleteVulnerability(t *testing.T) {
	unlinkPath := fmt.Sprintf("/var/lib/docker/buildkit/executor/%s/rootfs/tmp/stage/delete_me_proof_of_concept", executionId)
	unlinkEvent := unlink.Event{Pid: 1, Path: unlinkPath}
	cacheUnlinkEvent(executionId, &unlinkEvent)
	symlinkEvent := symlink.Event{Pid: 1, Target: "/", Linkpath: "/tmp/stage"}
	cacheSymlinkEvent(executionId, &symlinkEvent)
	executionEvents, _ := eventsMap.Get(executionId)
	assert.True(t, detectContainerTeardownDeleteVulnerability(executionEvents.(*buildkitExecutionEvents)))
}
