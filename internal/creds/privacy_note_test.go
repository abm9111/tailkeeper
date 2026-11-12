package creds

import (
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/config"
	"github.com/abm9111/tailkeeper/internal/privacy"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// A privacy key the owner appears to have set and that did not load must be said, because
// nothing in a result would: masking goes on without pseudonyms. An absent key is a choice
// and has no note. A note says which line or variable and what is wrong with it, and holds
// no value and no text of a line: the lines below carry the key itself.
func TestLoadPrivacyKeyExplainsAKeyThatLooksSetAndDidNotLoad(t *testing.T) {
	key := strings.Repeat("5a", 32)
	empty, blank := absPath("/run/secrets/empty"), absPath("/run/secrets/blank")
	files := map[string]string{empty: "", blank: " \r\n\t\n", "/c.env": ""}
	set := func(name, value string) map[string]string { return map[string]string{name: value} }
	envP, fileP := config.Provider{Provider: "env"}, config.Provider{Provider: "file", Path: "/c.env"}
	for _, c := range []struct {
		name    string
		p       config.Provider
		vars    map[string]string
		lookup  bool   // the variables are seen through LookupEnv, so that an empty one is set
		file    string // the credential file of the file provider
		wantKey bool
		note    string // what the note must contain; "" is no note
	}{
		{"env: absent", envP, nil, true, "", false, ""},
		{"env: a valid key", envP, set(privacy.EnvKey, key), true, "", true, ""},
		{"env: set but empty", envP, set(privacy.EnvKey, ""), true, "", false, "TAILKEEPER_PRIVACY_KEY is set but empty"},
		{"env: set but empty, seen through Getenv alone", envP, set(privacy.EnvKey, ""), false, "", false, ""},
		{"env: blank", envP, set(privacy.EnvKey, " \t"), false, "", false, "TAILKEEPER_PRIVACY_KEY is set but empty"},
		{"exec: set but empty", config.Provider{Provider: "exec"}, set(privacy.EnvKey, ""), true, "", false, "TAILKEEPER_PRIVACY_KEY is set but empty"},
		{"env: names an empty file", envP, set(privacy.EnvKey, "file:"+empty), false, "", false, "TAILKEEPER_PRIVACY_KEY names a file that holds nothing"},
		{"env: names a blank file", envP, set(privacy.EnvKey, "file:"+blank), false, "", false, "TAILKEEPER_PRIVACY_KEY names a file that holds nothing"},
		{"oidc: stores no secret", config.Provider{Provider: "oidc", ClientID: "c"}, set(privacy.EnvKey, ""), true, "", false, ""},
		{"file: absent", fileP, nil, true, "OTHER=1\n", false, ""},
		{"file: a valid key", fileP, nil, true, privacy.EnvKey + "=" + key + "\n", true, ""},
		{"file: an empty value", fileP, nil, true, "OTHER=1\n" + privacy.EnvKey + "=\n", false, "line 2 of the credential file gives TAILKEEPER_PRIVACY_KEY no value"},
		{"file: a quoted empty value", fileP, nil, true, privacy.EnvKey + "=\"\"\n", false, "line 1 of the credential file gives TAILKEEPER_PRIVACY_KEY no value"},
		{"file: names an empty file", fileP, nil, true, privacy.EnvKey + "=file:" + empty + "\n", false, "line 1 of the credential file names a file for TAILKEEPER_PRIVACY_KEY that holds nothing"},
		{"file: an export prefix", fileP, nil, true, "# keys\nexport " + privacy.EnvKey + "=" + key + "\n", false, "line 2 of the credential file names TAILKEEPER_PRIVACY_KEY but is not a NAME=value line for it"},
		{"file: another spelling of the name", fileP, nil, true, "tailkeeper_privacy_key=" + key + "\n", false, "line 1 of the credential file names TAILKEEPER_PRIVACY_KEY but is not a NAME=value line for it"},
		{"file: a byte order mark on the first line", fileP, nil, true, "\ufeff" + privacy.EnvKey + "=" + key + "\n", false, "line 1 of the credential file names TAILKEEPER_PRIVACY_KEY but is not a NAME=value line for it"},
		{"file: a quoted name", fileP, nil, true, "OTHER=1\n\"" + privacy.EnvKey + "\"=" + key + "\n", false, "line 2 of the credential file names TAILKEEPER_PRIVACY_KEY but is not a NAME=value line for it"},
		{"file: a single-quoted name", fileP, nil, true, "'" + privacy.EnvKey + "'=" + key + "\n", false, "line 1 of the credential file names TAILKEEPER_PRIVACY_KEY but is not a NAME=value line for it"},
		{"file: a byte order mark and a quoted name", fileP, nil, true, "\ufeff\"" + privacy.EnvKey + "\"=" + key + "\n", false, "line 1 of the credential file names TAILKEEPER_PRIVACY_KEY but is not a NAME=value line for it"},
		{"file: an export prefix and a quoted name", fileP, nil, true, "export \"" + privacy.EnvKey + "\"=" + key + "\n", false, "line 1 of the credential file names TAILKEEPER_PRIVACY_KEY but is not a NAME=value line for it"},
		{"file: a byte order mark before another name is no warning", fileP, nil, true, "\ufeffOTHER=1\n" + privacy.EnvKey + "=" + key + "\n", true, ""},
		{"file: a byte order mark line beside a valid one is harmless", fileP, nil, true, "\ufeff" + privacy.EnvKey + "=" + key + "\n" + privacy.EnvKey + "=" + key + "\n", true, ""},
		{"file: a name that only contains the key's name is no warning", fileP, nil, true, "MY_" + privacy.EnvKey + "_FILE=/x\n", false, ""},
		{"file: a comment is not a line", fileP, nil, true, "# export " + privacy.EnvKey + "=" + key + "\n", false, ""},
		{"file: an export line beside a valid one is harmless", fileP, nil, true, "export " + privacy.EnvKey + "=" + key + "\n" + privacy.EnvKey + "=" + key + "\n", true, ""},
		{"file: a later empty assignment wins, as it does for the key", fileP, nil, true, privacy.EnvKey + "=" + key + "\n" + privacy.EnvKey + "=\n", false, "line 2 of the credential file gives TAILKEEPER_PRIVACY_KEY no value"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := sys(c.vars, files)
			if c.p.Provider == "file" {
				files["/c.env"] = c.file
			}
			if c.lookup {
				s.LookupEnv = func(k string) (string, bool) { v, ok := c.vars[k]; return v, ok }
			}
			k, note, err := LoadPrivacyKey(c.p, s)
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if (k != nil) != c.wantKey {
				t.Errorf("key loaded = %v, want %v", k != nil, c.wantKey)
			}
			if (c.note == "") != (note == "") || !strings.Contains(note, c.note) {
				t.Errorf("note = %q, want one containing %q", note, c.note)
			}
			if strings.Contains(note, key) || strings.Contains(note, "export "+privacy.EnvKey+"=") || strings.Contains(note, "/c.env") || strings.Contains(note, empty) {
				t.Errorf("the note holds a value, a line or a path: %q", note)
			}
		})
	}
}

// What failed is an error and has no note: the note is for a key that nothing refused.
func TestLoadPrivacyKeyKeepsItsErrorsAndGivesThemNoNote(t *testing.T) {
	bad := strings.Repeat("5a", 30)
	k, note, err := LoadPrivacyKey(config.Provider{Provider: "env"}, sys(map[string]string{privacy.EnvKey: bad}, nil))
	if k != nil || note != "" || code(err) != tkerr.PrivacyKeyUnavailable || strings.Contains(err.Error(), bad) {
		t.Errorf("a malformed key: key %v, note %q, err %v", k, note, err)
	}
	// PrivacyKey, which the note does not concern, answers as it always has.
	if k, err := PrivacyKey(config.Provider{Provider: "env"}, sys(map[string]string{privacy.EnvKey: ""}, nil)); k != nil || err != nil {
		t.Errorf("PrivacyKey of an empty variable = %v, %v; want nil, nil", k, err)
	}
}
