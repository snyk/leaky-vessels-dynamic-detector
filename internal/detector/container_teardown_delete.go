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

import "strings"

const (
	containerTeardownDeleteCve      = "CVE-2024-23652"
	containerTeardownDeleteName     = "Buildkit Build-time Container Teardown Arbitrary Delete"
	containerTeardownDeleteBlogLink = "https://snyk.io/blog/cve-2024-23652-buildkit-build-time-container-teardown-arbitrary-delete"
)

func detectContainerTeardownDeleteVulnerability(executionEvents *buildkitExecutionEvents) bool {
	for _, unlinkEvent := range executionEvents.unlinkEvents {
		unlinkPath := unlinkEvent.Path
		containerRootFsLastComponent := "/rootfs/"
		index := strings.Index(unlinkPath, containerRootFsLastComponent)
		if index < 0 {
			continue
		}

		// Get /a/b/c instead of /var/lib/docker/buildkit/executor/piq6gktw74lvrr039b0m8x9kw/rootfs/a/b/c
		truncatedUnlinkPath := unlinkPath[index+len(containerRootFsLastComponent)-1:]
		for _, symlinkEvent := range executionEvents.symlinkEvents {
			if strings.HasPrefix(truncatedUnlinkPath, symlinkEvent.Linkpath) {
				// We're in the same container, the unlinked path is contained in the symlink target
				return true
			}
		}
	}

	return false
}
