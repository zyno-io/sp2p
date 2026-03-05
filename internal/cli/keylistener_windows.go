// SPDX-License-Identifier: MIT

//go:build windows

package cli

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procReadConsoleInput  = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")
	procWriteConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("WriteConsoleInputW")
)

const keyEventType = 0x0001

// inputRecord mirrors the Windows INPUT_RECORD structure.
type inputRecord struct {
	eventType uint16
	_         uint16   // padding
	event     [16]byte // union (KEY_EVENT_RECORD is 16 bytes)
}

// keyEventRecord mirrors the Windows KEY_EVENT_RECORD structure.
type keyEventRecord struct {
	keyDown         int32
	repeatCount     uint16
	virtualKeyCode  uint16
	virtualScanCode uint16
	char            uint16 // UnicodeChar
	controlKeyState uint32
}

// KeyListener reads single keypresses from the console and sends them on
// a channel. Returns nil from NewKeyListener if the console is unavailable.
type KeyListener struct {
	handle windows.Handle
	Keys   chan byte
	done   chan struct{}
}

// NewKeyListener opens the console input and starts reading key events.
// No console mode flags are modified, so Ctrl+C and VT processing are
// unaffected. Returns nil if the console cannot be opened.
func NewKeyListener() *KeyListener {
	name, _ := windows.UTF16PtrFromString("CONIN$")
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return nil
	}

	// Verify it's a console handle.
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		windows.CloseHandle(handle)
		return nil
	}

	kl := &KeyListener{
		handle: handle,
		Keys:   make(chan byte, 8),
		done:   make(chan struct{}),
	}
	go kl.readLoop()
	return kl
}

func (kl *KeyListener) readLoop() {
	var rec inputRecord
	var numRead uint32
	for {
		// Check for stop before blocking on the next read.
		select {
		case <-kl.done:
			return
		default:
		}
		ret, _, _ := procReadConsoleInput.Call(
			uintptr(kl.handle),
			uintptr(unsafe.Pointer(&rec)),
			1,
			uintptr(unsafe.Pointer(&numRead)),
		)
		if ret == 0 {
			return
		}
		if rec.eventType != keyEventType || numRead == 0 {
			continue
		}
		key := (*keyEventRecord)(unsafe.Pointer(&rec.event))
		if key.keyDown == 0 || key.char == 0 {
			continue
		}
		select {
		case kl.Keys <- byte(key.char):
		case <-kl.done:
			return
		}
	}
}

// Done returns a channel that is closed when the key listener is stopped.
func (kl *KeyListener) Done() <-chan struct{} {
	return kl.done
}

// Stop unblocks the read loop and closes the console handle.
// On Windows, CloseHandle can block if ReadConsoleInputW has a pending
// read, so we inject a dummy event first to wake the reader.
func (kl *KeyListener) Stop() {
	select {
	case <-kl.done:
		return // already stopped
	default:
		close(kl.done)
	}
	// Inject a dummy key event to unblock ReadConsoleInputW.
	// The readLoop checks done before the next read, so it will exit.
	var rec inputRecord
	rec.eventType = keyEventType
	key := (*keyEventRecord)(unsafe.Pointer(&rec.event))
	key.keyDown = 1
	key.char = 0 // null char, filtered by readLoop
	var written uint32
	procWriteConsoleInput.Call(
		uintptr(kl.handle),
		uintptr(unsafe.Pointer(&rec)),
		1,
		uintptr(unsafe.Pointer(&written)),
	)
	windows.CloseHandle(kl.handle)
}
