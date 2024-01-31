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
	"ebpf-detector/internal/mnt"
	"ebpf-detector/internal/utils"
	"fmt"
	"os"
	"regexp"
	"strings"
)

var layerFsRegex = regexp.MustCompile("/var/lib/docker/overlay2/[a-zA-Z0-9]{24,}/diff/")

const (
	cacheRaceCve      = "CVE-2024-23651"
	cacheRaceName     = "Buildkit Mount Cache Race: Build-time Race Condition Container Breakout"
	cacheRaceBlogLink = "https://snyk.io/blog/cve-2024-23651-docker-buildkit-mount-cache-race-build-time-race-condition-container-breakout"
)

func detectCacheRaceVulnerability(event *mnt.Event) {
	var dirName = event.DirName
	var resolvedTarget string
	if processSelfFdRegex.MatchString(dirName) {
		// Resolve symlink as early as possible to avoid a race against the process going down
		dirName = strings.Replace(dirName, "/self/", fmt.Sprintf("/%d/", event.Pid), 1)
		resolvedTarget, _ = os.Readlink(dirName)
	} else if utils.IsSymlink(dirName) {
		resolvedTarget, _ = os.Readlink(dirName)
	}

	pi := extractProcessInfo(event.Pid)
	if !isDockerDaemonOperation(&pi) {
		return
	}

	if !layerFsRegex.MatchString(event.DevName) || !utils.IsSymlink(event.DevName) {
		return
	}

	forensics := map[string]any{"PID": event.Pid, "Mount source": event.DevName, "Mount target": event.DirName}
	if executorRootFsRegex.MatchString(dirName) {
		Reporter(cacheRaceCve, cacheRaceName, cacheRaceBlogLink, forensics)
	} else if executorRootFsRegex.MatchString(resolvedTarget) {
		forensics["Resolved mount target symlink"] = resolvedTarget
		Reporter(cacheRaceCve, cacheRaceName, cacheRaceBlogLink, forensics)
	}
}
