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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLdflagsParsing(t *testing.T) {
	version, commit := extractVersionInfo("-w -X \"github.com/docker/docker/dockerversion.Version=24.0.7\" -X \"github.com/docker/docker/dockerversion.GitCommit=311b9ff\" -X \"github.com/docker/docker/dockerversion.BuildTime=2023-10-26T09:08:26.000000000+00:00\" -X \"github.com/docker/docker/dockerversion.PlatformName=Docker Engine - Community\" -X \"github.com/docker/docker/dockerversion.ProductName=docker\" -X \"github.com/docker/docker/dockerversion.DefaultProductLicense=\"")
	assert.Equal(t, version, "24.0.7")
	assert.Equal(t, commit, "311b9ff")
}
