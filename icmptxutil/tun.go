package icmptxutil

import (
	"os"
	"syscall"
	"unsafe"
)

const (
	cIFNAMSIZ  = 0x10
	cIFF_TUN   = 0x0001
	cIFF_TAP   = 0x0002
	cIFF_NO_PI = 0x1000
)

type ifReq struct {
	name  [cIFNAMSIZ]byte
	flags uint16
}

func OpenTun() (*os.File, error) {
	var ifr ifReq

	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifr.flags = cIFF_TUN | cIFF_NO_PI

	err = ioctl(f.Fd(), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func ioctl(fd uintptr, request int, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}
