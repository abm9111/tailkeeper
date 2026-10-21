package acl

import (
	"strings"
	"testing"
)

// Probe A-1 (20 Oct 2026): a test that denies a destination fails with "acls" absent (the
// default allow-all), passes with "acls": [], and passes with "grants": [] and no "acls". So an
// empty grants section is deny-all like an empty acls section. Not measured: a non-empty
// grants section with no acls.
func TestAnEmptyGrantsSectionIsDenyAllLikeAnEmptyAcls(t *testing.T) {
	for name, c := range map[string]struct {
		text string
		want State
	}{
		"grants empty":          {`{"grants": []}`, StateEmpty},
		"acls empty":            {`{"acls": []}`, StateEmpty},
		"both empty":            {`{"acls": [], "grants": []}`, StateEmpty},
		"grants null is absent": {`{"grants": null}`, StateAbsent},
		"nothing":               {`{}`, StateAbsent},
	} {
		if got := normalise(t, c.text).AccessState(); got != c.want {
			t.Errorf("%s: AccessState = %v, want %v", name, got, c.want)
		}
	}
	for dir, ab := range [][2]string{{`{}`, `{"grants": []}`}, {`{"grants": []}`, `{}`}} {
		r := diff(t, ab[0], ab[1])
		ch := find(t, r, ClassDefaults, "acls+grants")
		if r.Counts.Defaults != 1 || ch.Old.Text == ch.New.Text {
			t.Errorf("direction %d: %d defaults changes, %q to %q", dir, r.Counts.Defaults, ch.Old.Text, ch.New.Text)
		}
		if ch.Note != defaultsNote {
			t.Errorf("direction %d: the note is %q, want the defaults note", dir, ch.Note)
		}
	}
	if r := diff(t, `{}`, `{"grants": []}`); find(t, r, ClassDefaults, "acls+grants").New.Text != "empty" {
		t.Error("absent to an empty grants section must read as empty")
	}
}

func TestTheDefaultsNoteSaysWhatIsMeasured(t *testing.T) {
	g := `{"src": ["a@example.com"], "dst": ["tag:x"], "ip": ["*"]}`
	// One note on the pooled move and one on a single section written as [] beside the other.
	pooled := find(t, diff(t, `{}`, `{"acls": []}`), ClassDefaults, "acls+grants").Note
	single := find(t, diff(t, `{"grants": [`+g+`]}`, `{"acls": [], "grants": [`+g+`]}`), ClassDefaults, "acls").Note
	for name, note := range map[string]string{"the pooled move": pooled, "a single section": single} {
		for _, want := range []string{"grants", "empty acls or grants section is deny-all", "measured against the live API", "was not measured"} {
			if !strings.Contains(note, want) {
				t.Errorf("%s: the note %q lacks %q", name, note, want)
			}
		}
		if strings.Contains(note, "is not known") {
			t.Errorf("%s: the note still says it is not known: %q", name, note)
		}
	}
}

// Probe A-5 (20 Oct 2026): the server rejects nodeAttr as an unknown field and accepts
// attrConfig, extraDNSRecords and sshTests.
func TestKnownSectionsAgreeWithProbeA5(t *testing.T) {
	if s, ok := SectionByName("nodeAttr"); ok {
		t.Errorf("nodeAttr is a section (%q); the server rejects it", s.Name)
	}
	for _, name := range []string{"attrConfig", "extraDNSRecords", "sshTests"} {
		if _, ok := SectionByName(name); !ok {
			t.Errorf("%s is not a section; the server accepts it", name)
		}
	}
	found := map[string]bool{}
	for _, s := range Sections() {
		found[s.Name] = true
	}
	if found["nodeAttr"] || !found["attrConfig"] || !found["extraDNSRecords"] || !found["sshTests"] {
		t.Errorf("Sections() disagrees with the probe: %v", found)
	}
}
