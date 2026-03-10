// SPDX-License-Identifier: MIT

package archive

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// TarReader streams a directory as a tar archive.
type TarReader struct {
	pr *io.PipeReader
}

// NewTarReader creates a reader that produces a tar stream from a directory.
// The tar is created in a background goroutine for streaming without temp files.
func NewTarReader(dir string) (*TarReader, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeTar(pw, dir))
	}()

	return &TarReader{pr: pr}, nil
}

func (t *TarReader) Read(p []byte) (int, error) {
	return t.pr.Read(p)
}

// Close closes the tar reader.
func (t *TarReader) Close() error {
	return t.pr.Close()
}

// NewTarReaderFromPaths creates a reader that produces a tar stream from
// multiple files and/or directories. Each entry is stored with its basename.
func NewTarReaderFromPaths(paths []string) (*TarReader, error) {
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			return nil, err
		}
	}

	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeTarPaths(pw, paths))
	}()

	return &TarReader{pr: pr}, nil
}

func writeTarPaths(w io.Writer, paths []string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := addDirToTar(tw, p); err != nil {
				return err
			}
		} else {
			if err := addFileToTar(tw, p, info); err != nil {
				return err
			}
		}
	}
	return nil
}

func addFileToTar(tw *tar.Writer, path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return nil
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.Base(path)
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(tw, f)
	if closeErr := f.Close(); closeErr != nil && copyErr == nil {
		return closeErr
	}
	return copyErr
}

func addDirToTar(tw *tar.Writer, dir string) error {
	baseDir := filepath.Base(dir)
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		name := filepath.ToSlash(filepath.Join(baseDir, rel))
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		if closeErr := f.Close(); closeErr != nil && copyErr == nil {
			return closeErr
		}
		return copyErr
	})
}

func writeTar(w io.Writer, dir string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	baseDir := filepath.Base(dir)

	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Compute relative path.
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		// Prefix with the base directory name.
		name := filepath.Join(baseDir, rel)
		name = filepath.ToSlash(name) // normalize to forward slashes

		// Skip the root directory entry itself.
		if rel == "." {
			return nil
		}

		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = name

		// Security: only regular files and directories.
		if !info.Mode().IsRegular() && !info.IsDir() {
			return nil // skip symlinks, devices, etc.
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		if closeErr := f.Close(); closeErr != nil && copyErr == nil {
			return closeErr
		}
		return copyErr
	})
}

// TarInfo holds pre-computed tar stream statistics.
type TarInfo struct {
	Size      uint64 // exact byte length of the tar stream
	FileCount int    // number of regular files
}

// ComputeTarInfo walks paths and returns the exact tar stream size and file count.
// This matches the output of NewTarReader / NewTarReaderFromPaths.
func ComputeTarInfo(paths []string) (TarInfo, error) {
	var info TarInfo
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return info, err
		}
		if st.IsDir() {
			if err := tarInfoDir(p, &info); err != nil {
				return info, err
			}
		} else if st.Mode().IsRegular() {
			info.FileCount++
			info.Size += 512 // tar header
			info.Size += (uint64(st.Size()) + 511) &^ uint64(511) // data padded to 512
		}
	}
	info.Size += 1024 // end-of-archive marker
	return info, nil
}

func tarInfoDir(dir string, info *TarInfo) error {
	return filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil // root directory skipped, matching writeTar
		}
		if fi.IsDir() {
			info.Size += 512 // directory header
		} else if fi.Mode().IsRegular() {
			info.FileCount++
			info.Size += 512 // file header
			info.Size += (uint64(fi.Size()) + 511) &^ uint64(511)
		}
		return nil
	})
}

const (
	// maxEntries is the maximum number of entries in a tar archive.
	maxEntries = 100_000
	// maxPathLen is the maximum length of a tar entry path.
	maxPathLen = 4096
	// maxPathDepth is the maximum directory depth of a tar entry path.
	maxPathDepth = 100
)

// StagedExtraction holds a completed extraction in a staging directory.
// Call Commit to move files to the final destination, or Rollback to clean up.
type StagedExtraction struct {
	StagingDir string // temp dir containing extracted files
	DestDir    string // final destination (absolute, symlinks resolved)
}

// Extract reads a tar stream into a staging directory without moving to dest.
// Call Commit() on the result to finalize, or Rollback() to clean up.
func Extract(r io.Reader, destDir string) (*StagedExtraction, error) {
	tr := tar.NewReader(r)

	absDest, err := filepath.Abs(destDir)
	if err != nil {
		return nil, err
	}
	// Resolve symlinks in destDir itself so comparisons work on systems
	// where temp directories are behind symlinks (e.g. macOS /var -> /private/var).
	absDest, err = filepath.EvalSymlinks(absDest)
	if err != nil {
		return nil, err
	}

	// Extract into a private temp directory to prevent TOCTOU races.
	// The temp dir is created with 0700 permissions so only the owner can access it,
	// eliminating symlink-based attacks between check and use.
	tmpDir, err := os.MkdirTemp(absDest, ".sp2p-extract-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp extraction dir: %w", err)
	}

	staged := &StagedExtraction{StagingDir: tmpDir, DestDir: absDest}

	var entryCount int

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			staged.Rollback()
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		entryCount++
		if entryCount > maxEntries {
			staged.Rollback()
			return nil, fmt.Errorf("tar archive exceeds maximum entry count (%d)", maxEntries)
		}

		// Security validation.
		if err := validateTarPath(header.Name); err != nil {
			staged.Rollback()
			return nil, fmt.Errorf("unsafe tar entry: %w", err)
		}
		if len(header.Name) > maxPathLen {
			staged.Rollback()
			return nil, fmt.Errorf("tar entry path too long: %d bytes (max %d)", len(header.Name), maxPathLen)
		}
		if pathDepth(header.Name) > maxPathDepth {
			staged.Rollback()
			return nil, fmt.Errorf("tar entry path too deep: %q (max depth %d)", header.Name, maxPathDepth)
		}

		// Build target inside the private temp dir.
		target := filepath.Join(tmpDir, header.Name)

		// Verify the target is within tmpDir.
		if !strings.HasPrefix(target, tmpDir+string(os.PathSeparator)) && target != tmpDir {
			staged.Rollback()
			return nil, fmt.Errorf("tar entry %q escapes destination directory", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				staged.Rollback()
				return nil, err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				staged.Rollback()
				return nil, err
			}
			// Sanitize file mode: strip setuid/setgid/sticky bits, cap at 0755.
			mode := os.FileMode(header.Mode) & 0o755
			// O_EXCL prevents following symlinks and ensures exclusive creation.
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, mode)
			if err != nil {
				staged.Rollback()
				return nil, err
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if copyErr != nil {
				staged.Rollback()
				return nil, copyErr
			}
			if closeErr != nil {
				staged.Rollback()
				return nil, fmt.Errorf("closing %s: %w", header.Name, closeErr)
			}
		default:
			// Skip symlinks, hardlinks, devices, etc.
			continue
		}
	}

	return staged, nil
}

// Commit moves extracted files from staging to destination.
func (s *StagedExtraction) Commit() error {
	entries, err := os.ReadDir(s.StagingDir)
	if err != nil {
		return fmt.Errorf("reading extracted entries: %w", err)
	}
	for _, entry := range entries {
		src := filepath.Join(s.StagingDir, entry.Name())
		dst := filepath.Join(s.DestDir, entry.Name())
		// Refuse to overwrite existing paths in the destination.
		if _, err := os.Lstat(dst); err == nil {
			return fmt.Errorf("refusing to overwrite existing path: %s", entry.Name())
		}
		if err := os.Rename(src, dst); err != nil {
			return fmt.Errorf("moving %s to destination: %w", entry.Name(), err)
		}
	}
	// Remove the now-empty staging dir.
	os.Remove(s.StagingDir)
	return nil
}

// Rollback removes the staging directory and all its contents.
func (s *StagedExtraction) Rollback() {
	os.RemoveAll(s.StagingDir)
}

// Untar extracts a tar stream to a directory.
// It validates all paths for safety (no absolute paths, no traversal).
// Extraction uses a private temp directory to prevent TOCTOU races.
func Untar(r io.Reader, destDir string) error {
	staged, err := Extract(r, destDir)
	if err != nil {
		return err
	}
	if err := staged.Commit(); err != nil {
		staged.Rollback()
		return err
	}
	return nil
}

func pathDepth(name string) int {
	return len(strings.Split(filepath.ToSlash(name), "/"))
}

func validateTarPath(name string) error {
	if filepath.IsAbs(name) {
		return fmt.Errorf("absolute path: %s", name)
	}
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if part == ".." {
			return fmt.Errorf("path traversal: %s", name)
		}
	}
	return nil
}
