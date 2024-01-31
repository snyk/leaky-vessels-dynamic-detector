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
	"ebpf-detector/internal/chdir"
	"ebpf-detector/internal/utils"
	"os"
)

const (
	workdirCve      = "CVE-2024-21626"
	workdirName     = "runc process.cwd & Leaked FDs Container Breakout"
	workdirBlogLink = "https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout"
)

func detectWorkdirVulnerability(event *chdir.Event, path string, recursionDepth uint8) {
	if recursionDepth >= 50 {
		// Avoid infinite loop
		return
	}

	if processSelfFdRegex.MatchString(path) {
		forensics := map[string]any{"PID": event.Pid, "WORKDIR path": event.Path}
		Reporter(workdirCve, workdirName, workdirBlogLink, forensics)
		return
	}

	// Path is relative to process root fs, convert it to absolute
	absPath := utils.GetProcessFsPath(path, event.Pid)
	if !utils.IsSymlink(absPath) {
		// Not a symlink, nothing left to do
		return
	}

	link, err := os.Readlink(absPath)
	if err != nil {
		// Unable to resolve the link, nothing left to do
		return
	}

	detectWorkdirVulnerability(event, link, recursionDepth+1)
}
