package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/debug"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/rw"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/require"
)

type DockerOptions struct {
	Image      string
	EntryPoint string
	Ports      []uint16
	Cmd        []string
	Env        []string
	Bind       map[string]string
	Stdin      []byte
	Cap        []string
}

func startDockerContainer(t *testing.T, options DockerOptions) {
	t.Helper()
	dockerClient, containerID, _ := createDockerContainer(t, options)
	require.NoError(t, dockerClient.ContainerStart(t.Context(), containerID, container.StartOptions{}))
	if len(options.Stdin) > 0 {
		stdinAttach, err := dockerClient.ContainerAttach(t.Context(), containerID, container.AttachOptions{
			Stdin:  true,
			Stream: true,
		})
		require.NoError(t, err)
		_, err = stdinAttach.Conn.Write(options.Stdin)
		require.NoError(t, err)
		stdinAttach.Close()
	}
	if debug.Enabled {
		attach, err := dockerClient.ContainerAttach(t.Context(), containerID, container.AttachOptions{
			Stdout: true,
			Stderr: true,
			Logs:   true,
			Stream: true,
		})
		require.NoError(t, err)
		t.Cleanup(attach.Close)
		go func() {
			stdcopy.StdCopy(os.Stderr, os.Stderr, attach.Reader)
		}()
	}
	time.Sleep(time.Second)
}

func createDockerContainer(t *testing.T, options DockerOptions) (*client.Client, string, func()) {
	t.Helper()
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	t.Cleanup(func() { _ = dockerClient.Close() })

	var containerOptions container.Config
	if len(options.Stdin) > 0 {
		containerOptions.OpenStdin = true
		containerOptions.StdinOnce = true
	}

	containerOptions.Image = options.Image
	if options.EntryPoint != "" {
		containerOptions.Entrypoint = []string{options.EntryPoint}
	}
	containerOptions.Cmd = options.Cmd
	containerOptions.Env = options.Env
	containerOptions.ExposedPorts = make(nat.PortSet)

	var hostOptions container.HostConfig
	hostOptions.NetworkMode = "host"
	hostOptions.CapAdd = options.Cap
	hostOptions.PortBindings = make(nat.PortMap)

	for _, port := range options.Ports {
		containerOptions.ExposedPorts[nat.Port(F.ToString(port, "/tcp"))] = struct{}{}
		containerOptions.ExposedPorts[nat.Port(F.ToString(port, "/udp"))] = struct{}{}
		hostOptions.PortBindings[nat.Port(F.ToString(port, "/tcp"))] = []nat.PortBinding{
			{HostPort: F.ToString(port), HostIP: "0.0.0.0"},
		}
		hostOptions.PortBindings[nat.Port(F.ToString(port, "/udp"))] = []nat.PortBinding{
			{HostPort: F.ToString(port), HostIP: "0.0.0.0"},
		}
	}

	if len(options.Bind) > 0 {
		hostOptions.Binds = []string{}
		for path, internalPath := range options.Bind {
			if !rw.FileExists(path) {
				path = filepath.Join("config", path)
			}
			path, _ = filepath.Abs(path)
			hostOptions.Binds = append(hostOptions.Binds, path+":"+internalPath)
		}
	}

	dockerContainer, err := dockerClient.ContainerCreate(t.Context(), &containerOptions, &hostOptions, nil, nil, "")
	require.NoError(t, err)
	remove := sync.OnceFunc(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := dockerClient.ContainerRemove(ctx, dockerContainer.ID, container.RemoveOptions{Force: true, RemoveVolumes: true})
		if !client.IsErrNotFound(err) {
			require.NoError(t, err)
		}
	})
	t.Cleanup(remove)
	return dockerClient, dockerContainer.ID, remove
}

func readDockerLogs(ctx context.Context, dockerClient *client.Client, containerID string) ([]byte, error) {
	logs, err := dockerClient.ContainerLogs(ctx, containerID, container.LogsOptions{ShowStdout: true, ShowStderr: true})
	if err != nil {
		return nil, err
	}
	defer logs.Close()
	var output bytes.Buffer
	_, err = stdcopy.StdCopy(&output, &output, logs)
	return output.Bytes(), err
}
