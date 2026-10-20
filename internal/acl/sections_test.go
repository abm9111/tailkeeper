package acl

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	tsclient "tailscale.com/client/tailscale/v2"
)

func TestSectionsAreTheTwentyTheSpecNames(t *testing.T) {
	want := "acls autoApprovers grants groups hosts ipsets nodeAttrs postures ssh sshTests tagOwners tests " +
		"derpMap disableIPv4 OneCGNATRoute randomizeClientPort defaultSrcPosture extraDNSRecords externalTailnets attrConfig"
	var got []string
	for _, s := range sections {
		got = append(got, s.Name)
	}
	if strings.Join(got, " ") != want {
		t.Errorf("sections:\n got  %s\n want %s", strings.Join(got, " "), want)
	}
}

func TestSectionByNameIgnoresCaseButNotSpelling(t *testing.T) {
	for _, name := range []string{"acls", "ACLs", "TAGOWNERS", "tagowners", "oneCGNATRoute", "OneCGNATRoute", "ONECGNATROUTE", "sshtests", "DefaultSrcPosture"} {
		if _, ok := SectionByName(name); !ok {
			t.Errorf("%q is not found", name)
		}
	}
	if s, _ := SectionByName("ACLS"); s.Name != "acls" {
		t.Errorf("ACLS found %q", s.Name)
	}
	// nodeAttr is not an alias of nodeAttrs; case folding does not make them equal.
	for _, name := range []string{"nodeAttr", "NodeAttr", "acl", "tag_owners", ""} {
		if s, ok := SectionByName(name); ok {
			t.Errorf("%q is found as %q", name, s.Name)
		}
	}
	if sectionPos("nodeAttrs") < 0 || sectionPos("nodeAttr") != -1 {
		t.Error("sectionPos does not agree with SectionByName")
	}
}

func TestEverySectionHasAnOrderAndShape(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range sections {
		if s.Order == 0 || s.Shape == 0 {
			t.Errorf("%s: no order or shape in the table", s.Name)
		}
		if k := sectionKey(s.Name); seen[k] {
			t.Errorf("%s repeats a section under case folding", s.Name)
		} else {
			seen[k] = true
		}
		switch s.Shape {
		case ShapeScalar:
			if s.Order != OrderNone {
				t.Errorf("%s: a scalar has no order", s.Name)
			}
		case ShapeMap, ShapeStruct, ShapeRules, ShapeSet, ShapeTests, ShapeNodeAttrs, ShapeList:
		default:
			t.Errorf("%s: unknown shape %d", s.Name, s.Shape)
		}
	}
	// Today every array section is order-insensitive, and so are the arrays inside the
	// maps, except the operation lists of ipsets and the node lists of derpMap, which are
	// processed in order.
	for _, s := range sections {
		sensitive := s.Order == OrderSensitive
		if want := s.Name == "ipsets" || s.Name == "derpMap"; sensitive != want {
			t.Errorf("%s: order sensitive = %v, want %v", s.Name, sensitive, want)
		}
	}
}

// The table is private and Sections hands out a copy: a caller that edits what it got cannot
// make the table disagree with the index built from it.
func TestSectionsHandsOutACopyOfTheTable(t *testing.T) {
	got := Sections()
	if len(got) != len(sections) || !reflect.DeepEqual(got, sections) {
		t.Fatalf("Sections() is not the table: %v", got)
	}
	got[0].Name = "changed"
	got[0].Order = OrderSensitive
	if sections[0].Name != "acls" || sections[0].Order != OrderInsensitive {
		t.Errorf("an edit of the copy reached the table: %+v", sections[0])
	}
	if s, ok := SectionByName("acls"); !ok || s.Name != "acls" {
		t.Errorf("SectionByName(acls) = %+v, %v after an edit of the copy", s, ok)
	}
}

// Section.Order is documentation of a rule that the readers apply elsewhere (keyedOpts,
// structOpts and the shapes), so the two are compared here for every section: an array inside
// the section, written in the other order, reads as the same policy exactly when the table
// says the section is order-insensitive. A section without an array has no order. A new section
// has no sample until one is added, which fails the test.
func TestSectionOrderIsWhatTheReadersDo(t *testing.T) {
	samples := map[string][2]string{
		"acls":              {`{"acls": [{"action": "accept", "src": ["a"], "dst": ["x:1"]}, {"action": "accept", "src": ["b"], "dst": ["y:2"]}]}`, `{"acls": [{"action": "accept", "src": ["b"], "dst": ["y:2"]}, {"action": "accept", "src": ["a"], "dst": ["x:1"]}]}`},
		"grants":            {`{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["80", "443"]}]}`, `{"grants": [{"src": ["a"], "dst": ["x"], "ip": ["443", "80"]}]}`},
		"autoApprovers":     {`{"autoApprovers": {"routes": {"192.0.2.0/24": ["a", "b"]}}}`, `{"autoApprovers": {"routes": {"192.0.2.0/24": ["b", "a"]}}}`},
		"groups":            {`{"groups": {"group:a": ["x", "y"]}}`, `{"groups": {"group:a": ["y", "x"]}}`},
		"ipsets":            {`{"ipsets": {"ipset:a": ["add 192.0.2.1", "add 192.0.2.2"]}}`, `{"ipsets": {"ipset:a": ["add 192.0.2.2", "add 192.0.2.1"]}}`},
		"nodeAttrs":         {`{"nodeAttrs": [{"target": ["*"], "attr": ["a", "b"]}]}`, `{"nodeAttrs": [{"target": ["*"], "attr": ["b", "a"]}]}`},
		"postures":          {`{"postures": {"posture:a": ["x", "y"]}}`, `{"postures": {"posture:a": ["y", "x"]}}`},
		"ssh":               {`{"ssh": [{"action": "accept", "src": ["a"], "dst": ["b"], "users": ["u", "v"]}]}`, `{"ssh": [{"action": "accept", "src": ["a"], "dst": ["b"], "users": ["v", "u"]}]}`},
		"sshTests":          {`{"sshTests": [{"src": "a", "dst": ["b"], "accept": ["u", "v"]}]}`, `{"sshTests": [{"src": "a", "dst": ["b"], "accept": ["v", "u"]}]}`},
		"tagOwners":         {`{"tagOwners": {"tag:a": ["x", "y"]}}`, `{"tagOwners": {"tag:a": ["y", "x"]}}`},
		"tests":             {`{"tests": [{"src": "a", "accept": ["x:1", "y:2"]}]}`, `{"tests": [{"src": "a", "accept": ["y:2", "x:1"]}]}`},
		"derpMap":           {`{"derpMap": {"regions": {"1": {"nodes": [{"name": "a"}, {"name": "b"}]}}}}`, `{"derpMap": {"regions": {"1": {"nodes": [{"name": "b"}, {"name": "a"}]}}}}`},
		"defaultSrcPosture": {`{"defaultSrcPosture": ["a", "b"]}`, `{"defaultSrcPosture": ["b", "a"]}`},
		"extraDNSRecords":   {`{"extraDNSRecords": [{"Name": "a.example.com", "Type": "A", "Value": "192.0.2.1"}, {"Name": "b.example.com", "Type": "A", "Value": "192.0.2.2"}]}`, `{"extraDNSRecords": [{"Name": "b.example.com", "Type": "A", "Value": "192.0.2.2"}, {"Name": "a.example.com", "Type": "A", "Value": "192.0.2.1"}]}`},
		"externalTailnets":  {`{"externalTailnets": {"x": {"allowExternalReferencesTo": ["a", "b"]}}}`, `{"externalTailnets": {"x": {"allowExternalReferencesTo": ["b", "a"]}}}`},
		"attrConfig":        {`{"attrConfig": {"x": {"broadcastToPeers": ["a", "b"]}}}`, `{"attrConfig": {"x": {"broadcastToPeers": ["b", "a"]}}}`},
	}
	for _, sec := range sections {
		sample, ok := samples[sec.Name]
		switch sec.Order {
		case OrderNone:
			if ok {
				t.Errorf("%s has no order, yet a sample", sec.Name)
			}
			continue
		case OrderInsensitive, OrderSensitive:
		default:
			t.Errorf("%s: order %d", sec.Name, sec.Order)
			continue
		}
		if !ok {
			t.Errorf("%s: add a sample of its order to this test", sec.Name)
			continue
		}
		r := diff(t, sample[0], sample[1])
		if equal := r.SemanticallyEqual; equal != (sec.Order == OrderInsensitive) {
			t.Errorf("%s: a reordered array reads as unchanged = %v, but the table says order %d", sec.Name, equal, sec.Order)
		}
	}
	for name := range samples {
		if _, ok := SectionByName(name); !ok {
			t.Errorf("a sample for %s, which is no section", name)
		}
	}
}

// missingFromTable lists the sections a struct declares (by the name in its hujson tags)
// that the table lacks, compared without regard to case.
func missingFromTable(typ reflect.Type) []string {
	var missing []string
	for i := 0; i < typ.NumField(); i++ {
		tag, ok := typ.Field(i).Tag.Lookup("hujson")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		if _, known := SectionByName(name); !known {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	return missing
}

// The client struct is Tailscale's own list of sections. A bump of the dependency that
// adds one fails here until the table has it. The comparison is one-directional: the
// struct has no sshTests or extraDNSRecords, which the table keeps, and the case of its
// hujson tags differs from the table's spellings (DerpMap, IPSets, DefaultSrcPosture),
// hence the case folding.
func TestSectionsCoverTheClientStruct(t *testing.T) {
	if missing := missingFromTable(reflect.TypeOf(tsclient.ACL{})); len(missing) > 0 {
		t.Errorf("tailscale.com/client/tailscale/v2 declares sections the table lacks: %v", missing)
	}
}

// The check can fail: a struct with a section the table does not know is reported.
func TestTheClientStructCheckFindsAMissingSection(t *testing.T) {
	type future struct {
		ACLs      []string `hujson:"ACLs,omitempty"`
		Quotas    string   `hujson:"Quotas,omitempty"`
		NodeAttr  []string `hujson:"NodeAttr"`
		Untagged  string
		Skipped   string `hujson:"-"`
		JSONOnly  string `json:"jsonOnly"`
		OneCGNAT  string `hujson:"oneCGNATRoute"`
		Unlabeled string `hujson:",omitempty"`
	}
	got := missingFromTable(reflect.TypeOf(future{}))
	if !reflect.DeepEqual(got, []string{"NodeAttr", "Quotas"}) {
		t.Errorf("missing = %v, want [NodeAttr Quotas]", got)
	}
}

func TestFoldKeyIsGoSimpleFolding(t *testing.T) {
	for _, pair := range [][2]string{{"src", "SRC"}, {"Src", "sRc"}, {"tests", "Tests"}, {"k", "\u212a"}, {"s", "\u017f"}, {"\u00dfx", "\u1e9ex"}} {
		if foldKey(pair[0]) != foldKey(pair[1]) {
			t.Errorf("%q and %q should fold alike", pair[0], pair[1])
		}
	}
	if foldKey("src") == foldKey("dst") || foldKey("nodeAttr") == foldKey("nodeAttrs") {
		t.Error("different names fold alike")
	}
}
