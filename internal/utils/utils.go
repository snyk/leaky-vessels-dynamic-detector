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
package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var hostRootFs = os.Getenv("HOST_ROOT_FS")

func IsSymlink(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return false
	}

	return fi.Mode()&os.ModeSymlink != 0
}

func ConvertCString(cString []byte) string {
	for i := 0; i < len(cString); i++ {
		if cString[i] == 0 {
			return string(cString[:i])
		}
	}
	return string(cString)
}

func GetProcessFsPath(processRelativePath string, pid uint32) string {
	return filepath.Join(getProcFolder(pid), "root", processRelativePath)
}

func GetProcessCmdline(pid uint32) string {
	cmdline := filepath.Join(getProcFolder(pid), "cmdline")
	bytes, err := os.ReadFile(cmdline)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(strings.ReplaceAll(string(bytes), "\x00", " "))
}

func GetProcessPpid(pid uint32) (uint32, error) {
	statPath := filepath.Join(getProcFolder(pid), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) >= 4 {
		// See https://man7.org/linux/man-pages/man5/proc.5.html (under /proc/pid/stat)
		parsed, err := strconv.Atoi(fields[3])
		if err != nil {
			return 0, err
		} else {
			return uint32(parsed), nil
		}
	}

	return 0, nil
}

func getProcFolder(pid uint32) string {
	procFolder := fmt.Sprintf("/proc/%d", pid)
	if hostRootFs != "" {
		// In K8s, host fs is mounted to a directory in the pod,
		// so we need to add it as a prefix
		procFolder = filepath.Join(hostRootFs, procFolder)
	}

	return procFolder
}
