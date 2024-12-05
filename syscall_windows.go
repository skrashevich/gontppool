//go:build windows

package main

import "syscall"

func SetsockoptInt(fd uintptr, level, opt int, value int) (err error) {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, opt, value)
}

func SetsockoptIPMreq(fd uintptr, level, opt int, mreq *syscall.IPMreq) (err error) {
	return syscall.SetsockoptIPMreq(syscall.Handle(fd), level, opt, mreq)
}
func Chroot(path string) (err error) {
	return nil
}
func Setgid(gid int) (err error) {
	return nil
}
func Setuid(uid int) (err error) {
	return nil
}
