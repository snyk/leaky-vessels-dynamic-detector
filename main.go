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
//go:build linux

package main

import (
	"ebpf-detector/internal/chdir"
	"ebpf-detector/internal/detector"
	"ebpf-detector/internal/dockerd"
	"ebpf-detector/internal/logger"
	"ebpf-detector/internal/mnt"
	"ebpf-detector/internal/symlink"
	"ebpf-detector/internal/unlink"
	"os"
)

func main() {
	detector.Reporter = exploitationReporter

	if os.Getenv("RUNTIME_MODE") != "true" {
		detectBuildTimeVulnerabilities()
	}

	chdir.Listen(func(event *chdir.Event) {
		detector.HandleChdirEvent(event)
	})
}

func detectBuildTimeVulnerabilities() {
	if !dockerd.InstrumentDockerDaemon(func(event *dockerd.Event) {
		detector.HandleDockerdEvent(event)
	}) {
		logger.Info("Could not find docker daemon / docker daemon's buildkit version is patched")
		return
	}
	go mnt.Listen(func(event *mnt.Event) {
		detector.HandleMountEvent(event)
	})
	go symlink.Listen(func(event *symlink.Event) {
		detector.HandleSymlinkEvent(event)
	})
	go unlink.Listen(func(event *unlink.Event) {
		detector.HandleUnlinkEvent(event)
	})
}

func exploitationReporter(cve, name, blogUrl string, forensics map[string]any) {
	logger.Info("Leaky Vessels vulnerability detected", "CVE", cve, "Name", name, "Blogpost URL", blogUrl, "Forensics", forensics)
}
