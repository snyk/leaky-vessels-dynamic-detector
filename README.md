# Leaky Vessels Dynamic Detector

![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/d7a72392dd568658c2009a161803959466595094/oss-community.jpg)

In this repository you'll find a reference implementation for an eBPF-based runtime detection for the runc and Docker vulnerabilities `CVE-2024-21626`, `CVE-2024-23651`, `CVE-2024-23652` and `CVE-2024-23653`. It hooks into Linux syscalls (e.g., `chdir`, `mount`) and function invocations of the Docker daemon and associates them with Docker builds and container processes to identify exploitations of these vulnerabilities.
For a static analysis-based approach, please see [this](https://github.com/snyk/leaky-vessels-static-detector). 

### runc process.cwd & Leaked fds Container Breakout [CVE-2024-21626]

CVE-2024-21626 is a vulnerability in the `runc` container runtime allowing an attacker to break out of the container isolation and achieve full root RCE via a crafted image that exploits an issue within the `WORKDIR` instruction's handling. Since there's a "race" condition between the time some file descriptors to the host are opened and closed, an attacker can create a Dockerfile with the following instruction `WORKDIR /proc/self/fd/[ID]` (with ID being a system dependent file descriptor) that will point to the underlying host machine's file system. This can be exploited when running:


1. `docker build` - In 2 cases:
   - When the Dockerfile being built contains the exploit triggerting instruction.
   - When the Dockerfile being built refers to a base image via the `FROM` instruction that contains an `ONBUILD` command triggering the exploit e.e. `ONBUILD WORKDIR /proc/self/fd/[ID]`. The `ONBUILD` instruction injects the command not in the image that contains it but in the image that uses it as a base image. This means that if a base image is compromised or intentionally nefarious i.e. hosted on Dockerhub or other public container registries, exploitation if possible even if nothing changes in the image that the `docker build` command actually builds.  
2. `docker run`


Thus, this vulnerability can put both build systems and production environments at risk.

### Buildkit Mount Cache Race: Build-time Race Condition Container Breakout [CVE-2024-23651]

CVE-2024-23651 is a vulnerability in Docker where a `RUN` command is using the `--mount=cache` flag. There's a time-of-check/time-of-use (TOCTOU) vulnerability between the check that a `source` dir exists on the Docker daemon's host and the actual call to the `mount` syscall. An attacker is able to craft a Dockerfile that would plant a symlink in between these two calls to induce an arbitrary bind mount that results in full root RCE on the host.
This vulnerability only affects the `docker build` command.

### Buildkit GRPC SecurityMode Privilege Check [CVE-2024-23653]

CVE-2024-23653 is a vulnerability in Docker that occurs when using a custom Buildkit LLB generator is used with the `# syntax` directive. The generator can use the Client.NewContainer and Container.Start GRPC calls to execute a new container during build. The StartRequest.SecurityMode argument is not appropriately checked against the privilege expectations of the docker daemon or docker build call, which allows the GRPC caller to create a privileged container during build. This new privileged container can then be escaped to gain full root RCE on the build host.
This vulnerability only affects the `docker build` command.

### Buildkit Build-time Container Teardown Arbitrary Delete [CVE-2024-23652]

CVE-2024-23652 is an arbitrary deletion vulnerability in Docker. When `RUN --mount` is used in a Dockerfile, if the target of the mount does not exist it will be created for that environment. When the execution completes this created directory will be cleaned up. If the executing command changes the path used for the mount to a symbolic link, the cleanup procedure will traverse this symbolic link and potentially clean up arbitrary directories in the host root filesystem.
This vulnerability only affects the `docker build` command.

## Installation & usage

### Build-time eBPF detection

The build-time detection applies to all 4 vulnerabilities.

1. Compile the detector binary: `GOOS=linux GOARCH={{amd64/arm64}} go build`.
2. Run the compiled binary in the background using `sudo` (as required by eBPF) in your build environment (i.e., `sudo ebpf-detector &`).
3. If an exploitation of one of the vulnerabilities is detected, you'll see `Leaky vessels vulnerability detected` printed to `STDOUT`, alongside the respective CVE, vulnerability name and additional forensics.

### Kubernetes run-time eBPF detection

The run-time detection applies the `WORKDIR` vulnerability only (CVE-2024-21626).

1. Build the container image of the detector using the provided `Dockerfile` and push it to an image registry.
2. Populate the `image` value in the `detector.yaml` (marked with `TODO`).
3. Run the detector as a DaemonSet in your Kubernetes cluster by running `kubectl apply -f detector.yml`.
4. If a WORKDIR vulnerability exploitation is detected, you'll see `Leaky Vessels vulnerability detected` printed in the DaemonSet pod logs.

## Testing

Unit tests need to run in `sudo`, as they rely on eBPF: `sudo go test ebpf-detector/...`.

## Limitations

* Requires root access / running containers in privileged mode (required by eBPF).
* The runtime `WORKDIR` exploitation (`CVE-2024-21626`) happens during container initialization, so it won't be detected on running containers. The detection also assumes the container runtime is `containerd`.
* The Buildkit Mount Cache Race (`CVE-2024-23651`) and Buildkit Build-time Container Teardown Arbitrary Delete (`CVE-2024-23652`) detections are timing-based and may have false negatives due to race conditions.
* Tested in the following environments:
    - Ubuntu 20.04/22.04 (AMD64)
    - GKE (Ubuntu and Alpine Linux, AMD64)
    - EKS (Ubuntu and Alpine Linux, AMD64)
    - Ubuntu 22.04 (ARM64)

## Issues
For updated list of bugs and issues see the project issues. 

## Contributing
Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License
The Leaky Vessels Dynamic Detector is under the Apache-2.0 license. See [LICENSE](LICENSE) for more information.
