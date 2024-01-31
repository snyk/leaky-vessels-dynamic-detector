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
package dockerd

import (
	"bufio"
	"bytes"
	"ebpf-detector/internal/logger"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	goVersion "github.com/hashicorp/go-version"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -type event bpf dockerd.c -- -I../../headers
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event bpf dockerd.c -- -I../../headers

const (
	funcSymbol                 = "github.com/moby/buildkit/frontend/gateway.(*gatewayContainer).Start"
	ldflagsArgs                = "-ldflags="
	GrpcPrivilegeCheckCve      = "CVE-2024-23653"
	GrpcPrivilegeCheckName     = "Buildkit GRPC SecurityMode Privilege Check"
	GrpcPrivilegeCheckBlogLink = "https://snyk.io/blog/cve-2024-23653-buildkit-grpc-securitymode-privilege-check"
)

type Event struct {
	Pid        uint32
	BinaryPath string
	FuncSymbol string
}

type ExploitDetectionHandler func(*Event)

func InstrumentDockerDaemon(handler ExploitDetectionHandler) bool {
	dockerd := findDockerdBinaries()
	if len(dockerd) == 0 {
		logger.Warn("Could not find the docker daemon binary")
		return false
	}

	binaryFound := false
	for _, binaryPath := range dockerd {
		ldflagsArg, buildkitVersion := extractInfoFromBinary(binaryPath)
		if ldflagsArg == "" || buildkitVersion == "" {
			continue
		}

		if isPatchedBuildkitVersion(buildkitVersion) {
			logger.Info("Buildkit is patched, skipping docker daemon binary", "version", buildkitVersion, "docker daemon binary", binaryPath)
			continue
		}

		binaryFound = true
		version, commitHash := extractVersionInfo(ldflagsArg)
		logger.Info("Attaching uprobe to docker daemon", "docker daemon binary", binaryPath, "version", version, "commit hash", commitHash, "buildkit version", buildkitVersion)
		attachUprobe(binaryPath, funcSymbol, handler)
	}

	return binaryFound
}

func isPatchedBuildkitVersion(version string) bool {
	if strings.HasPrefix(version, "v") {
		// Remove "v" prefix
		version = version[1:]
	}

	patchedVersion, _ := goVersion.NewVersion("0.12.5")
	currVersion, err := goVersion.NewVersion(version)
	if err != nil {
		logger.Error(err, "Could not parse buildkit version", "version", version)
		return false
	}

	return currVersion.GreaterThanOrEqual(patchedVersion)
}

func findDockerdBinaries() []string {
	dockerdBinaries := []string{}
	filepath.WalkDir("/", func(path string, d fs.DirEntry, err error) error {
		if d.Name() == "dockerd" && !d.IsDir() {
			dockerdBinaries = append(dockerdBinaries, path)
		}

		return nil
	})

	return dockerdBinaries
}

func extractVersionInfo(ldflags string) (string, string) {
	versionKey := "github.com/docker/docker/dockerversion.Version"
	commitKey := "github.com/docker/docker/dockerversion.GitCommit"
	var version string
	var commit string
	for _, arg := range strings.Split(ldflags, "-X") {
		if strings.Contains(arg, versionKey) {
			keyVal, err := strconv.Unquote(strings.TrimSpace(arg))
			if err == nil {
				version = strings.Split(keyVal, "=")[1]
			}

		} else if strings.Contains(arg, commitKey) {
			keyVal, err := strconv.Unquote(strings.TrimSpace(arg))
			if err == nil {
				commit = strings.Split(keyVal, "=")[1]
			}
		}

	}

	return version, commit
}

// Extract the ldflags arg and buildkit dependency version
func extractInfoFromBinary(binaryPath string) (string, string) {
	file, err := os.Open(binaryPath)
	if err != nil {
		logger.Error(err, "Could not open dockerd binary: "+binaryPath)
		return "", ""
	}
	defer file.Close()

	var ldflagsArg string
	var buildkitVersion string
	scanner := bufio.NewScanner(file)
	scanner.Split(scanBinaryForStrings)
	for scanner.Scan() {
		token := scanner.Text()
		if token == "build" {
			// A text line in the Go binary that describes a build arg looks like:
			// build   -ldflags="-w -X \"github.com/docker/docker/dockerversion.Version=24.0.7\" -X \"github.com/docker/docker/dockerversion.GitCommit=311b9ff\" -X \"github.com/docker/docker/dockerversion.BuildTime=2023-10-26T09:08:26.000000000+00:00\" -X \"github.com/docker/docker/dockerversion.PlatformName=Docker Engine - Community\" -X \"github.com/docker/docker/dockerversion.ProductName=docker\" -X \"github.com/docker/docker/dockerversion.DefaultProductLicense=\""
			scanner.Scan()
			buildArg := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(buildArg, ldflagsArgs) {
				trimmed := buildArg[len(ldflagsArgs):]
				res, err := strconv.Unquote(trimmed)
				if err != nil {
					logger.Error(err, "Could not unquote ldflags build arg", "binary path", binaryPath, "ldflags", buildArg)
					continue
				}

				ldflagsArg = res
				if buildkitVersion != "" {
					return ldflagsArg, buildkitVersion
				}
			}
		} else if token == "dep" {
			// A text line in the Go binary that describes the buildkit dependency would look like:
			// dep     github.com/moby/buildkit        v0.11.7-0.20230908085316-d3e6c1360f6e
			scanner.Scan()
			packageName := strings.TrimSpace(scanner.Text()) // Next token is the packagename
			if packageName == "github.com/moby/buildkit" {
				scanner.Scan()
				version := strings.TrimSpace(scanner.Text()) // Next token is the version, verify it starts with 'v'
				if !strings.HasPrefix(version, "v") {
					continue
				}

				buildkitVersion = version
				if ldflagsArg != "" {
					return ldflagsArg, buildkitVersion
				}

			}
		}
	}

	return ldflagsArg, buildkitVersion
}

func scanBinaryForStrings(data []byte, atEOF bool) (advance int, token []byte, err error) {
	for i := 0; i < len(data); i++ {
		if data[i] >= 32 && data[i] <= 126 {
			for j := i; j < len(data); j++ {
				if data[j] < 32 || data[j] > 126 {
					return j + 1, data[i:j], nil
				}
			}
			return len(data), data[i:], nil
		}
	}
	return len(data), nil, nil
}

func attachUprobe(binaryPath, funcSymbol string, handler ExploitDetectionHandler) bool {
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		logger.Error(err, "Failed loading dockerd bpf objects")
		return false
	}

	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		logger.Error(err, "Failed opening executable")
		objs.Close()
		return false
	}

	uprobe, err := ex.Uprobe(funcSymbol, objs.FuncHook, nil)
	if err != nil {
		objs.Close()
		return false
	}

	reader, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		logger.Error(err, "Could not open dockerd perf reader")
		objs.Close()
		uprobe.Close()
		return false
	}

	done := make(chan struct{})

	go func() {
		logger.Info("Waiting for function invocations for binary " + binaryPath)
		defer objs.Close()
		defer uprobe.Close()
		defer reader.Close()

		var event bpfEvent
		for {
			select {
			case <-done:
				return
			default:
				record, err := reader.Read()
				if err != nil {
					if errors.Is(err, perf.ErrClosed) {
						return
					}

					continue
				}

				if record.LostSamples != 0 {
					continue
				}

				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					continue
				}

				handler(&Event{event.Pid, binaryPath, funcSymbol})
			}
		}
	}()

	return true
}
