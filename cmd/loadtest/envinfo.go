package main

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type envInfo struct {
	GoVersion  string
	GOOS       string
	GOARCH     string
	NumCPU     int
	GOMAXPROCS int
	OSVersion  string
	RAMBytes   int64
}

func detectEnv() envInfo {
	e := envInfo{
		GoVersion:  runtime.Version(),
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		NumCPU:     runtime.NumCPU(),
		GOMAXPROCS: runtime.GOMAXPROCS(0),
	}
	switch runtime.GOOS {
	case "darwin":
		e.OSVersion = darwinOSVersion()
		e.RAMBytes = darwinRAMBytes()
	case "linux":
		e.OSVersion = linuxOSVersion()
		e.RAMBytes = linuxRAMBytes()
	}
	return e
}

func runCmdTrim(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func darwinOSVersion() string {
	productVersion := runCmdTrim("sw_vers", "-productVersion")
	kernelVersion := runCmdTrim("uname", "-r")
	switch {
	case productVersion == "" && kernelVersion == "":
		return ""
	case productVersion == "":
		return "Darwin " + kernelVersion
	case kernelVersion == "":
		return "macOS " + productVersion
	default:
		return "macOS " + productVersion + " (Darwin " + kernelVersion + ")"
	}
}

func darwinRAMBytes() int64 {
	out := runCmdTrim("sysctl", "-n", "hw.memsize")
	n, err := strconv.ParseInt(out, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func linuxOSVersion() string {
	return runCmdTrim("uname", "-a")
}

func linuxRAMBytes() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}
