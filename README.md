# Project - insert name here

This allows generation of C code from Go, it also automates the building of snippet code that can be used to start your eBPF program. 

## Required Packages (on Ubuntu at least)

- clang
- gcc-multilib
- libbpf-dev

## Usage

The `main.go` contains an example of building an eBPF program that uses TCP functionality and extracts some information from the packets being observed.

### Functions to be aware of

- `ebpf.FailSafeTimeOut(time, func())` - is used to close things after the timeout (incase you kill something important)
- `ebpf.Trace()` - Blocking call that watches debug logs (ctrl+c to exit)
