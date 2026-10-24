//go:build unix

package doctor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheStarterFileIsMode0600AndAnExistingFileASymlinkAndADirectoryAreRefused(t *testing.T) {
	f, a := newApp(t, allReadScopes(t))
	a.KeyID = ""
	dir := t.TempDir()
	path := filepath.Join(dir, "invariants.hujson")
	if _, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", fi.Mode().Perm())
	}
	kept, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := WriteStarter(context.Background(), a, StarterInput{Out: path, Tags: []string{"tag:db"}, AdminGroups: []string{"group:ops"}}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("existing file: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(kept) {
		t.Fatalf("existing file was changed")
	}
	link := filepath.Join(dir, "link.hujson")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteStarter(context.Background(), a, StarterInput{Out: link, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symlink: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(kept) {
		t.Fatal("symlink write changed the target")
	}
	if _, err := WriteStarter(context.Background(), a, StarterInput{Out: dir, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}}); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("directory: %v", err)
	}
	// The creation itself names each reason, whatever the early check said, and the early
	// check refuses all three before any token or API request.
	for path, want := range map[string]string{link: "symbolic link", dir: "directory", filepath.Join(dir, "invariants.hujson"): "already exists"} {
		if err := createStarter(path, []byte("{}\n")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("createStarter(%s) = %v, want %q", filepath.Base(path), err, want)
		}
		if err := CheckStarterInput(StarterInput{Out: path, Tags: []string{"tag:web"}, AdminGroups: []string{"group:admins"}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckStarterInput(%s) = %v, want %q", filepath.Base(path), err, want)
		}
	}
	if n := len(f.Requests()) + f.TokenRequests(); n != 0 {
		t.Errorf("%d requests were made for a path the starter refuses", n)
	}
}
