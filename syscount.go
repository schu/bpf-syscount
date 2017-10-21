package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <bpfprog> <pid>...\n", os.Args[0])
		os.Exit(1)
	}

	module := elf.NewModule(os.Args[1])
	err := module.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load program: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := module.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to close program: %v\n", err)
		}
	}()

	fmt.Println("Loaded BPF program")

	if err := module.EnableTracepoint("tracepoint/raw_syscalls/sys_enter"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enable tracepoint: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Enabled tracepoints")

	syscallCount := module.Map("syscall_count")
	if syscallCount == nil {
		fmt.Fprintf(os.Stderr, "Failed to load 'syscall_count' map\n")
		os.Exit(1)
	}

	syscallCountFd := syscallCount.Fd()

	if err := elf.PinObject(syscallCountFd, "/sys/fs/bpf/syscount"); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to pin 'syscall_count' map: %v\n", err)
		os.Exit(1)
	}

	pidsToWatch := module.Map("pids_to_watch")
	if pidsToWatch == nil {
		fmt.Fprintf(os.Stderr, "Failed to load 'pids_to_watch' map\n")
		os.Exit(1)
	}

	var one uint32 = 1
	for _, pidStr := range os.Args[2:] {
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to convert %q to int: %v\n", pidStr, err)
			os.Exit(1)
		}
		if err := module.UpdateElement(pidsToWatch, unsafe.Pointer(&pid), unsafe.Pointer(&one), 0); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add pid %d to watch list: %v\n", pid, err)
			os.Exit(1)
		}
		fmt.Printf("Tracing pid %d ...\n", pid)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Println("Abort with Ctrl+C")

	<-sig
}
