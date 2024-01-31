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
