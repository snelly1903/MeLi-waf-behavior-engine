package main

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// envInfo es la información de entorno para el reporte: SO/versión,
// arquitectura, CPU, RAM, Go version y GOMAXPROCS. OSVersion/RAMBytes
// se obtienen con comandos del propio sistema operativo (os/exec, sin
// dependencias nuevas) — nunca fallan de forma fatal: si el comando
// no está disponible o el SO no está soportado, quedan en "" / 0 y el
// reporte lo muestra como "desconocido", nunca bloquea la corrida por
// esto.
type envInfo struct {
	GoVersion  string
	GOOS       string
	GOARCH     string
	NumCPU     int
	GOMAXPROCS int
	OSVersion  string // "" si no se pudo determinar
	RAMBytes   int64  // 0 si no se pudo determinar
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
	// Mejor esfuerzo: uname -a ya da una sola línea razonablemente
	// completa (kernel + distro en la mayoría de los casos), sin
	// tener que parsear /etc/os-release con sus muchas variantes de
	// formato.
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
