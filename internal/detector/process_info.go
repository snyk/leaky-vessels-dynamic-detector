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
	"ebpf-detector/internal/utils"
	"strings"
)

type processInfo struct {
	pid       uint32
	cmdline   string
	ancestors []struct {
		pid     uint32
		cmdline string
	}
}

func extractProcessInfo(pid uint32) processInfo {
	cmdline := utils.GetProcessCmdline(pid)
	result := processInfo{
		pid:     pid,
		cmdline: cmdline,
		ancestors: []struct {
			pid     uint32
			cmdline string
		}{},
	}

	ppid, err := utils.GetProcessPpid(pid)
	for err == nil && ppid > 1 {
		result.ancestors = append(result.ancestors, struct {
			pid     uint32
			cmdline string
		}{ppid, utils.GetProcessCmdline(ppid)})
		ppid, err = utils.GetProcessPpid(ppid)
	}

	return result
}

func isDockerDaemonOperation(pi *processInfo) bool {
	if len(pi.ancestors) == 0 {
		return false
	}

	procInfo := pi.ancestors[len(pi.ancestors)-1]
	splitCmdline := strings.Fields(procInfo.cmdline)
	if len(splitCmdline) == 0 {
		return false
	}

	return strings.HasSuffix(splitCmdline[0], "/dockerd")
}

func isContainerOperation(pi *processInfo) bool {
	if len(pi.ancestors) == 0 {
		return false
	}

	procInfo := pi.ancestors[len(pi.ancestors)-1]
	splitCmdline := strings.Fields(procInfo.cmdline)
	if len(splitCmdline) == 0 {
		return false
	}

	// The root containerd container process command since 2019
	return strings.HasSuffix(splitCmdline[0], "/containerd-shim-runc-v2")
}
