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
package test_utils

import (
	"bufio"
	"context"
	"ebpf-detector/internal/logger"
	"io"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
)

func getDockerClient() *client.Client {
	client, err := client.NewClientWithOpts()
	if err != nil {
		panic(err)
	}

	return client
}

func BuildTarBall(rootPath string, includeFiles []string) (io.ReadCloser, error) {
	tar, err := archive.TarWithOptions(rootPath, &archive.TarOptions{IncludeFiles: includeFiles})
	if err != nil {
		panic(err)
	}
	return tar, err
}

func PullImage(image string) {
	client := getDockerClient()
	ctx := context.Background()
	if imageExists(ctx, client, image) {
		return
	}

	logger.Info("Pulling docker image: " + image)
	closer, err := client.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		panic(err)
	} else {
		defer closer.Close()
		scanner := bufio.NewScanner(closer)
		for scanner.Scan() {
			logger.Debug(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}
	logger.Info("Image pulled successfully")
}

func imageExists(ctx context.Context, cli *client.Client, imageName string) bool {
	images, err := cli.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return false
	}

	for _, image := range images {
		for _, tag := range image.RepoTags {
			if tag == imageName {
				return true
			}
		}
	}

	return false
}

func BuildImage(contents io.ReadCloser, dockerfile, imageTag string) {
	client := getDockerClient()
	ctx := context.Background()

	logger.Info("Building docker image: " + imageTag)
	opts := types.ImageBuildOptions{
		Dockerfile: dockerfile,
		Tags:       []string{imageTag},
		Remove:     true,
		NoCache:    true,
		Version:    types.BuilderBuildKit,
	}

	res, err := client.ImageBuild(ctx, contents, opts)
	if err != nil {
		panic(err)
	} else {
		defer res.Body.Close()
		scanner := bufio.NewScanner(res.Body)
		for scanner.Scan() {
			logger.Debug(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			panic(err)
		}
	}

	logger.Info("Image built successfully")
}
