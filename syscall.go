//go:build !(darwin || ios || freebsd || openbsd || netbsd || dragonfly || windows)

package main

import (
	"syscall"
)

func SetsockoptInt(fd uintptr, level, opt int, value int) (err error) {
	return syscall.SetsockoptInt(int(fd), level, opt, value)
}

func SetsockoptIPMreq(fd uintptr, level, opt int, mreq *syscall.IPMreq) (err error) {
	return syscall.SetsockoptIPMreq(int(fd), level, opt, mreq)
}
func Chroot(path string) (err error) {
	return syscall.Chroot(path)
}
func Setgid(gid int) (err error) {
	return syscall.Setgid(gid)
}
func Setuid(uid int) (err error) {
	return syscall.Setuid(uid)
}
