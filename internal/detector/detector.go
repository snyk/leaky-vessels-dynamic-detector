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
	"ebpf-detector/internal/dockerd"
	"ebpf-detector/internal/logger"
	"ebpf-detector/internal/mnt"
	"ebpf-detector/internal/symlink"
	"ebpf-detector/internal/unlink"
	"regexp"
)

const (
	processSelfFdStr       = "/proc/self/fd/[0-9]+"
	executorFolderRegexStr = "/var/lib/docker/buildkit/executor/([a-zA-Z0-9]{24,})"
	executorRootFsRegexStr = executorFolderRegexStr + "/rootfs/"
)

var (
	processSelfFdRegex  = regexp.MustCompile(processSelfFdStr)
	executorFolderRegex = regexp.MustCompile(executorFolderRegexStr)
	executorRootFsRegex = regexp.MustCompile(executorRootFsRegexStr)
)

type exploitationReporter func(cve, name, blogLink string, forensics map[string]any)

var Reporter exploitationReporter = nil

func HandleDockerdEvent(event *dockerd.Event) {
	forensics := map[string]any{"PID": event.Pid, "Docker Daemon path": event.BinaryPath}
	Reporter(dockerd.GrpcPrivilegeCheckCve, dockerd.GrpcPrivilegeCheckName, dockerd.GrpcPrivilegeCheckBlogLink, forensics)
}

func HandleMountEvent(event *mnt.Event) {
	logger.Debug("Mount syscall detected", "event", event)
	detectCacheRaceVulnerability(event)
}

func HandleSymlinkEvent(event *symlink.Event) {
	logger.Debug("Symlink syscall detected", "event", event)
	pi := extractProcessInfo(event.Pid)
	if !isDockerDaemonOperation(&pi) {
		return
	}

	parentCmdline := pi.ancestors[0].cmdline
	matches := executorFolderRegex.FindStringSubmatch(parentCmdline)
	if len(matches) != 2 {
		return
	}

	buildkitExecId := matches[1]
	executionEvents := cacheSymlinkEvent(buildkitExecId, event)
	if detectContainerTeardownDeleteVulnerability(&executionEvents) {
		forensics := map[string]any{"PID": event.Pid, "buildkit execution ID": buildkitExecId, "Symlink source": event.Linkpath, "Symlink target": event.Target}
		Reporter(containerTeardownDeleteCve, containerTeardownDeleteName, containerTeardownDeleteBlogLink, forensics)
	}
}

func HandleUnlinkEvent(event *unlink.Event) {
	logger.Debug("Unlink syscall detected", "event", event)
	matches := executorRootFsRegex.FindStringSubmatch(event.Path)
	if len(matches) != 2 {
		return
	}

	buildkitExecId := matches[1]
	executionEvents := cacheUnlinkEvent(buildkitExecId, event)
	if detectContainerTeardownDeleteVulnerability(&executionEvents) {
		forensics := map[string]any{"PID": event.Pid, "buildkit execution ID": buildkitExecId, "Unlink path": event.Path}
		Reporter(containerTeardownDeleteCve, containerTeardownDeleteName, containerTeardownDeleteBlogLink, forensics)
	}
}

func HandleChdirEvent(event *chdir.Event) {
	logger.Debug("Chdir syscall detected", "event", event)
	pi := extractProcessInfo(event.Pid)
	if !isDockerDaemonOperation(&pi) && !isContainerOperation(&pi) {
		// Vulnerability applies to both build time and run time
		return
	}

	detectWorkdirVulnerability(event, event.Path, 0)
}
