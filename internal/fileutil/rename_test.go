// SPDX-License-Identifier: MIT

package fileutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRenameNoReplace(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("unsupported platform")
	}
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			root := t.TempDir()
			src, dst := filepath.Join(root, "src"), filepath.Join(root, "dst")
			if directory {
				if err := os.Mkdir(src, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(dst, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dst, []byte("old"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := RenameNoReplace(src, dst); err == nil {
				t.Fatal("replaced existing target")
			}
			if _, err := os.Stat(src); err != nil {
				t.Fatal("source lost", err)
			}
			if err := os.Remove(dst); err != nil {
				t.Fatal(err)
			}
			if err := RenameNoReplace(src, dst); err != nil {
				t.Fatal(err)
			}
		})
	}
}
