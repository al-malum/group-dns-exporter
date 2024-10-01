package main

import (
	"fmt"
	"log"
	"main/internal/pdns"
	"os"
	"path/filepath"
	"strings"
)

// build var
var desiredPathPid string

// PIDFile stored the process id
type PIDFile struct {
	path string
}

// just suit for linux
func processExists(pid string) bool {
	if _, err := os.Stat(filepath.Join("/proc", pid)); err == nil {
		return true
	}
	return false
}

func checkPIDFILEAlreadyExists(path string) error {
	if pidByte, err := os.ReadFile(path); err == nil {
		pid := strings.TrimSpace(string(pidByte))
		if processExists(pid) {
			return fmt.Errorf("ensure the process:%s is not running pid file:%s", pid, path)
		}
	}
	return nil
}

// NewPIDFile create the pid file
func newPIDFile(path string) (*PIDFile, error) {
	if err := checkPIDFILEAlreadyExists(path); err != nil {
		return nil, err
	}

	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		return nil, err
	}
	return &PIDFile{path: path}, nil
}

// Remove the pid file
func (file PIDFile) removePid() error {
	return os.Remove(file.path)
}

func main() {
	pid, errPid := newPIDFile(desiredPathPid)
	if errPid != nil {
		log.Fatal("It is not possible to create a pid file: ", errPid)
	}
	defer pid.removePid()
	err := pdns.Run()
	if err != nil {
		log.Fatal("FATAL ERROR")
	}
}
