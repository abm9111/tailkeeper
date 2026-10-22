package tools_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/tools"
)

// A cursor identifies the comparison it was issued for as a reader of the result sees it: the
// two normal forms as they are shown, the section filter and the Tailscale-written option. It
// tells a reader nothing that policySha256 does not.

// sixtyGroups is a patch whose result runs past one page.
func sixtyGroups() string {
	var ops []string
	for i := 0; i < 60; i++ {
		ops = append(ops, fmt.Sprintf(`{"op":"add","path":"/groups/group:g%02d","value":[]}`, i))
	}
	return "[" + strings.Join(ops, ",") + "]"
}

// cursorFor serves live and returns the cursor of the first page of the comparison of the
// patch with it, and the digest of the live policy the result shows.
func cursorFor(t *testing.T, env func(*registry.Env) *registry.Env, live string) (cursor, sha string) {
	t.Helper()
	f, reg, e := apiEnv(t)
	serveLive(f, live, nil, nil)
	var out tools.ACLDiffOutput
	mustCall(t, reg, env(e), "acl_diff", patchCall(sixtyGroups()), &out)
	if !out.Truncated || out.NextChange == "" {
		t.Fatalf("the comparison fits one page, so it has no cursor: %+v", out.Counts)
	}
	return out.NextChange, out.Old.PolicySHA256
}

func plain(e *registry.Env) *registry.Env { return e }

func withKey(t *testing.T) func(*registry.Env) *registry.Env {
	return func(e *registry.Env) *registry.Env { k, _ := keyed(t, e); return k }
}

func liveWith(login string) string {
	return "{\"groups\": {\"group:x\": [\"" + login + "\"]}}\n"
}

// Two live policies whose logins differ and are shown alike (a…@example.com) give one cursor and
// one digest, as they give one policySha256: a caller who computes the cursor of a guessed
// policy cannot tell which of the two is live. A policy that is shown differently gives
// another.
func TestTwoLivePoliciesThatReadAlikeGiveOneCursor(t *testing.T) {
	amy, shaAmy := cursorFor(t, plain, liveWith("amy@example.com"))
	ann, shaAnn := cursorFor(t, plain, liveWith("ann@example.com"))
	amyAgain, _ := cursorFor(t, plain, liveWith("amy@example.com"))
	bob, shaBob := cursorFor(t, plain, liveWith("bob@example.org"))
	if shaAmy != shaAnn {
		t.Fatalf("policySha256 tells amy from ann: %s %s", shaAmy, shaAnn)
	}
	if amy != ann {
		t.Errorf("the cursor tells amy from ann: %s %s", amy, ann)
	}
	if amy != amyAgain {
		t.Errorf("the cursor of one policy changes between calls: %s %s", amy, amyAgain)
	}
	if shaAmy == shaBob || amy == bob {
		t.Errorf("a policy shown otherwise shares the cursor (%s %s) or the digest (%s %s)", amy, bob, shaAmy, shaBob)
	}
}

// With a privacy key the cursor is keyed: for a policy that holds no address, which is shown
// as it is, the cursor equals neither the unkeyed digest of the masked forms nor that of the
// real ones (the digest a caller can compute from the open source and the policy it guesses).
func TestAKeyedCursorEqualsNeitherUnkeyedDigest(t *testing.T) {
	live := "{\"groups\": {\"group:x\": [\"tag:ci\"]}}\n"
	keyedCursor, _ := cursorFor(t, withKey(t), live)
	masked, _ := cursorFor(t, plain, live)
	real, _ := cursorFor(t, show, live)
	if masked != real {
		t.Fatalf("a policy with no address is shown as it is, so the unkeyed cursors agree: %s %s", masked, real)
	}
	if keyedCursor == masked || keyedCursor == real {
		t.Errorf("the keyed cursor %s is an unkeyed digest (%s)", keyedCursor, masked)
	}
	again, _ := cursorFor(t, withKey(t), live)
	if again != keyedCursor {
		t.Errorf("the keyed cursor of one policy changes between calls: %s %s", keyedCursor, again)
	}
	// What a key names apart, the keyed cursor tells apart: the pseudonyms differ.
	amy, _ := cursorFor(t, withKey(t), liveWith("amy@example.com"))
	ann, _ := cursorFor(t, withKey(t), liveWith("ann@example.com"))
	if amy == ann {
		t.Errorf("a keyed cursor does not tell two users apart: %s", amy)
	}
}

// With personalData show the real forms are shown, and the cursor is of the real forms.
func TestACursorOfShownLoginsTellsThemApart(t *testing.T) {
	amy, _ := cursorFor(t, show, liveWith("amy@example.com"))
	ann, _ := cursorFor(t, show, liveWith("ann@example.com"))
	if amy == ann {
		t.Errorf("with the logins shown the cursor does not tell them apart: %s", amy)
	}
}

// A cursor is refused for a comparison it does not belong to, and continues the one it does.
func TestACursorContinuesItsOwnComparisonAndIsRefusedForAnother(t *testing.T) {
	f, reg, env := apiEnv(t)
	serveLive(f, liveWith("amy@example.com"), nil, nil)
	var first tools.ACLDiffOutput
	mustCall(t, reg, env, "acl_diff", patchCall(sixtyGroups()), &first)
	var second tools.ACLDiffOutput
	mustCall(t, reg, env, "acl_diff", `{"patch":`+jsonString(sixtyGroups())+`,"fromChange":`+jsonString(first.NextChange)+`}`, &second)
	if len(second.Changes) == 0 || second.Changes[0].Entry == first.Changes[0].Entry {
		t.Errorf("the cursor did not continue the listing: %+v", second.Changes)
	}
	// The same cursor for another live policy (another masked form) is refused.
	f2, reg2, env2 := apiEnv(t)
	serveLive(f2, liveWith("bob@example.org"), nil, nil)
	_, err := call(t, reg2, env2, "acl_diff", `{"patch":`+jsonString(sixtyGroups())+`,"fromChange":`+jsonString(first.NextChange)+`}`)
	if err == nil || !strings.Contains(err.Error(), "does not belong to this comparison") {
		t.Errorf("a cursor of another comparison: %v", err)
	}
}
