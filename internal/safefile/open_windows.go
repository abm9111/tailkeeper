//go:build windows

package safefile

import (
	"errors"
	"os"
	"syscall"
)

// errReparse is a symbolic link, a junction or another reparse point at the path. Any
// reparse point is refused, including a cloud placeholder that os.Lstat reports as a
// regular file: refusing one costs a copy of the file, following one could read another.
var errReparse = errors.New("it is a symbolic link, a junction or another reparse point (a OneDrive placeholder is one); those are refused")

// identity names one file: its volume's serial number and its index on the volume.
// os.Lstat does not read them on Windows: os.SameFile reads them later, by path, so a
// file put at the path after the inspection would compare equal to itself. identify
// reads them at the inspection, from a handle that does not follow a reparse point.
type identity struct{ vol, hi, lo uint32 }

func identify(path string, _ os.FileInfo) (identity, error) {
	h, err := openHandle(path, 0)
	if err != nil {
		return identity{}, err
	}
	defer func() { _ = syscall.CloseHandle(h) }() // read only
	return identityOf(h)
}

// openNoFollow opens path for reading without following a reparse point. Windows has
// no O_NOFOLLOW: a link put at the path after the inspection opens as itself, and the
// identity check refuses it.
func openNoFollow(path string) (*os.File, error) {
	h, err := openHandle(path, syscall.GENERIC_READ)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// is reports whether f, the opened file, is the file inspected, read from its handle.
func (id identity) is(f *os.File, _ os.FileInfo) (bool, error) {
	got, err := identityOf(syscall.Handle(f.Fd()))
	if err != nil {
		return false, err
	}
	return got == id, nil
}

func openHandle(path string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return syscall.CreateFile(p, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func identityOf(h syscall.Handle) (identity, error) {
	var i syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &i); err != nil {
		return identity{}, err
	}
	if i.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return identity{}, errReparse
	}
	return identity{vol: i.VolumeSerialNumber, hi: i.FileIndexHigh, lo: i.FileIndexLow}, nil
}
