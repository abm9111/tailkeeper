package tools

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCutURLsKeepsOnlyTheHost(t *testing.T) {
	token := strings.Repeat("Q", 24) // assembled at run time: no credential-shaped literal
	for in, want := range map[string]string{
		"created https://hooks.example.test/services/T0/B0/" + token + " for alerts": "created https://hooks.example.test/…[path sha256 ",
		"https://logs.example.test": "https://logs.example.test",
		"no url here":               "no url here",
	} {
		got := cutURLs(in)
		if !strings.HasPrefix(got, want) && !strings.Contains(got, want) {
			t.Errorf("cutURLs(%q) = %q, want it to contain %q", in, got, want)
		}
		if strings.Contains(got, token) || strings.Contains(got, "/services/") {
			t.Errorf("cutURLs(%q) = %q: the path survived", in, got)
		}
	}
	if got := cutURLs(`{"url":"https:\/\/hooks.example.test\/services\/` + token + `"}`); strings.Contains(got, token) {
		t.Errorf("an escaped-slash URL kept its path: %q", got)
	}
}

// Every spelling of a URL that text can hold is cut to its host, and the text
// around it stays: the URL ends where a quote, a space or an angle bracket does,
// and a backslash that only escapes the next character is not part of it.
func TestCutURLsReadsEverySpellingOfAURL(t *testing.T) {
	token := strings.Repeat("Q", 24)
	const host = "hooks.example.test"
	for name, c := range map[string]struct{ in, around string }{
		"plain":                     {"https://" + host + "/services/T0/" + token, ""},
		"http":                      {"http://" + host + "/services/T0/" + token, ""},
		"a port":                    {"https://" + host + ":8443/services/T0/" + token, ""},
		"upper case":                {"HTTPS://" + strings.ToUpper(host) + "/services/T0/" + token, ""},
		"only a query":              {"https://" + host + "?k=" + token, ""},
		"escaped slashes":           {`https:\/\/` + host + `\/services\/T0\/` + token, ""},
		"unicode-escaped slashes":   {`https:\u002f\u002f` + host + `\u002fservices\u002fT0\u002f` + token, ""},
		"unicode-escaped colon":     {`https\u003a\u002f\u002f` + host + `\u002fservices\u002f` + token, ""},
		"after a word character":    {"endpointhttps://" + host + "/services/T0/" + token, ""},
		"user info":                 {"https://" + "user:" + "pw" + "@" + host + "/services/T0/" + token, ""},
		"in JSON text":              {`{"u":"https://` + host + `/services/` + token + `","n":1}`, `","n":1}`},
		"in an escaped quote":       {`Post \"https://` + host + `/services/` + token + `\": dial tcp`, `\": dial tcp`},
		"in angle brackets":         {"<https://" + host + "/services/" + token + "> sent", "> sent"},
		"in a sentence":             {"created https://" + host + "/services/" + token + " for alerts", " for alerts"},
		"an apostrophe in the path": {"https://" + host + "/services/a'" + token, ""},
		"between apostrophes":       {"see 'https://" + host + "/services/" + token + "' now", " now"},
		"imitating a cut one":       {"https://" + host + "/…[path-sha256-0123456789ab]/" + token, ""},
	} {
		got := cutURLs(c.in)
		if strings.Contains(got, token) || strings.Contains(got, "services") || strings.Contains(got, "pw") {
			t.Errorf("%s: cutURLs(%q) = %q: the path survived", name, c.in, got)
		}
		if !strings.Contains(strings.ToLower(got), host) {
			t.Errorf("%s: cutURLs(%q) = %q: the host is gone", name, c.in, got)
		}
		if c.around != "" && !strings.Contains(got, c.around) {
			t.Errorf("%s: cutURLs(%q) = %q: lost the text after the URL (%q)", name, c.in, got, c.around)
		}
	}
	// Two URLs in one text are each cut.
	got := cutURLs("a https://one.example.test/" + token + " b https://two.example.test/" + token + " c")
	if strings.Contains(got, token) || !strings.Contains(got, "https://one.example.test/…") || !strings.Contains(got, "https://two.example.test/…") ||
		!strings.HasPrefix(got, "a ") || !strings.HasSuffix(got, " c") {
		t.Errorf("two URLs: %q", got)
	}
	// A URL that cannot be read is replaced whole: nothing of it is kept.
	if got := cutURLs("see https://%zz/" + token + " now"); strings.Contains(got, token) || !strings.Contains(got, "(a URL that could not be read)") {
		t.Errorf("an unreadable URL: %q", got)
	}
	// The hash is the one the webhook tools show for the same URL.
	url := "https://" + host + "/services/T0/" + token + "?x=1"
	if _, sum := endpoint(url); !strings.Contains(cutURLs(url), "[path sha256 "+sum[:12]+"]") {
		t.Errorf("cutURLs(%q) = %q, want the path hash %s", url, cutURLs(url), sum[:12])
	}
}

func TestRedactSecretsRemovesCredentialNamedValues(t *testing.T) {
	raw := json.RawMessage(`{"url":"https://logs.example.test","token":"PLANTED-STREAM-TOKEN","nested":{"clientSecret":"PLANTED-SECRET","size":12345678901234567},"name":"keep me"}`)
	got := string(redactSecrets(raw))
	if strings.Contains(got, "PLANTED") {
		t.Errorf("redactSecrets kept a credential-named value: %s", got)
	}
	if !strings.Contains(got, "keep me") || !strings.Contains(got, "12345678901234567") {
		t.Errorf("redactSecrets dropped or changed other values: %s", got)
	}
	if string(redactSecrets(json.RawMessage(`"a policy file with the word token in it"`))) != `"a policy file with the word token in it"` {
		t.Error("a string value must come back unchanged")
	}
}

// Whatever a credential-named key holds is removed, not only a string: a nested
// object under "token" would otherwise keep its secret. Only true, false and null
// say nothing a reader could use.
func TestRedactSecretsRemovesWhateverShapeTheValueHas(t *testing.T) {
	raw := json.RawMessage(`{"token":{"value":"PLANTED-OBJ","more":["PLANTED-IN-OBJ"]},"secret":["PLANTED-ARR",1],` +
		`"password":123456789,"apiKey":"PLANTED-KEY","password2":"PLANTED-P2","keep":[{"a":{"clientSecret":{"deep":"PLANTED-DEEP"}},"b":"ok"}],"list":[{"token":"PLANTED-LIST"}]}`)
	got := string(redactSecrets(raw))
	if strings.Contains(got, "PLANTED") || strings.Contains(got, "123456789") {
		t.Errorf("redactSecrets kept a credential-named value: %s", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got), &decoded); err != nil {
		t.Fatalf("the redacted value is not JSON: %v: %s", err, got)
	}
	if decoded["token"] != "[removed]" || decoded["secret"] != "[removed]" || decoded["password"] != "[removed]" {
		t.Errorf("removed values should read [removed]: %s", got)
	}
	if !strings.Contains(got, `"b":"ok"`) {
		t.Errorf("a value under another name was dropped: %s", got)
	}
	// true, false and null are kept, and with nothing removed the text is the API's.
	same := `{"token": true, "secret":false,"password" : null,"x":"y"}`
	if got := string(redactSecrets(json.RawMessage(same))); got != same {
		t.Errorf("nothing was removed, so the text must be unchanged: %s", got)
	}
}

func TestRedactSecretsKeyNames(t *testing.T) {
	for _, k := range []string{"token", "accessToken", "secret", "clientSecret", "client_secret", "password", "passwd",
		"apikey", "api_key", "api-key", "apiKey", "API_KEY", "x-api-key", "authkey", "auth_key", "auth-key", "authKey",
		"accesskey", "access_key", "access-key", "accessKey", "authorization", "Authorization", "credential", "credentials",
		"privatekey", "private_key", "private-key", "privateKey", "cookie", "Set-Cookie", "bearer", "bearerToken"} {
		raw := `{"` + k + `":"PLANTED","ok":"fine"}`
		got := string(redactSecrets(json.RawMessage(raw)))
		if strings.Contains(got, "PLANTED") || !strings.Contains(got, `"ok":"fine"`) {
			t.Errorf("key %q: %s", k, got)
		}
	}
	for _, k := range []string{"name", "url", "author", "monkey", "keyboard", "size", "description", "endpointUrl"} {
		raw := `{"` + k + `":"PLANTED"}`
		if got := string(redactSecrets(json.RawMessage(raw))); got != raw {
			t.Errorf("key %q is not a credential name, yet: %s", k, got)
		}
	}
}

// With nothing to remove the API's own text comes back, byte for byte; with
// something removed the rest is re-encoded without HTML escaping and with each
// number's exact text.
func TestRedactSecretsKeepsTheAPIsTextOrRewritesItFaithfully(t *testing.T) {
	same := "{ \"a\" : \"<b>&\\/x\\u003c</b>\" ,\n \"n\": 1.50, \"l\": [1, 2e3] }"
	if got := string(redactSecrets(json.RawMessage(same))); got != same {
		t.Errorf("nothing removed, text changed:\n got %s\nwant %s", got, same)
	}
	got := string(redactSecrets(json.RawMessage(`{"token":"x","html":"<b>&</b>","n":1.50,"e":2e3,"big":12345678901234567890123,"p":"a/b"}`)))
	for _, want := range []string{`"html":"<b>&</b>"`, `"n":1.50`, `"e":2e3`, `"big":12345678901234567890123`, `"p":"a/b"`} {
		if !strings.Contains(got, want) {
			t.Errorf("rewritten value lost %s: %s", want, got)
		}
	}
	if strings.Contains(got, `\u003c`) || strings.HasSuffix(got, "\n") {
		t.Errorf("HTML escaped or a newline left: %q", got)
	}
}

// A string that holds a JSON object or array holds its credentials too; any other
// string is text and stays.
func TestRedactSecretsReadsJSONInsideStrings(t *testing.T) {
	inner := `{"token":"PLANTED-INNER","n":1}`
	outer := string(redactSecrets(json.RawMessage(`{"policy":` + quoteJSON(inner) + `,"list":[` + quoteJSON(`[{"secret":"PLANTED-ARR"}]`) + `],"note":"the word token in text"}`)))
	if strings.Contains(outer, "PLANTED") {
		t.Errorf("a credential inside a JSON string survived: %s", outer)
	}
	if !strings.Contains(outer, "the word token in text") || !strings.Contains(outer, `\"n\":1`) {
		t.Errorf("other text changed: %s", outer)
	}
	text, changed := redactJSONText("  " + inner + " ")
	if !changed || strings.Contains(text, "PLANTED") || !strings.Contains(text, `"n":1`) {
		t.Errorf("redactJSONText = %q, %v", text, changed)
	}
	for _, s := range []string{"a policy file with the word token in it", `{"not": json`, `["unclosed"`, "", `{"token": true}`, `{"a":1}`, "12"} {
		if got, changed := redactJSONText(s); changed || got != s {
			t.Errorf("redactJSONText(%q) = %q, %v: text with nothing to remove must come back as it was", s, got, changed)
		}
	}
}

// A value that cannot be read cannot be shown: a truncated or doubled document
// could hold a credential the parser never reached.
func TestRedactSecretsFailsClosed(t *testing.T) {
	for _, raw := range []string{`{"token":"PLANTED"`, `{"a":1} {"token":"PLANTED"}`, `{"token":"PLANTED"}}`, `not json PLANTED`} {
		got := string(redactSecrets(json.RawMessage(raw)))
		if strings.Contains(got, "PLANTED") {
			t.Errorf("redactSecrets(%s) = %s", raw, got)
		}
	}
	for _, raw := range []string{`12`, `true`, `null`, `"x"`, ` "token" `} {
		if got := string(redactSecrets(json.RawMessage(raw))); got != raw {
			t.Errorf("redactSecrets(%s) = %s, want it unchanged", raw, got)
		}
	}
}

// A policy file is HuJSON: comments and trailing commas. The old and new values of a
// policy edit are that text in a string, so a string that is not strict JSON but is
// HuJSON is read, and its credential-named values are removed as they are from JSON.
// With nothing to remove it comes back as the API sent it, byte for byte; text that is
// neither JSON nor HuJSON stays as it is.
func TestRedactJSONTextReadsHuJSON(t *testing.T) {
	policy := "{\n  // who may reach what\n  \"grants\": [{\"src\": [\"*\"], \"dst\": [\"*\"],}], /* kept */\n  \"token\": \"PLANTED-HU\", // trailing comma follows\n}\n"
	for name, in := range map[string]string{
		"comments and a trailing comma": policy,
		"padded":                        "  \n" + policy + "\n  ",
		"an array":                      "[ // list\n {\"secret\": \"PLANTED-HU\",},\n]",
		"a block comment":               `{"a": 1, /* c */ "password": "PLANTED-HU"}`,
		"nested":                        `{"outer": {"inner": [{"api_key": "PLANTED-HU",},],},}`,
		"a repeated key":                `{"token": "PLANTED-HU", "token": true,}`,
		"a nested key in a block":       "{\"a\": { // c\n \"authorization\": \"PLANTED-HU\" } , }",
		"HuJSON in a JSON string":       quoteJSON(policy),
		"a string in a string":          quoteJSON(quoteJSON(policy)),
	} {
		got, changed := redactJSONText(in)
		if !changed || strings.Contains(got, "PLANTED") {
			t.Errorf("%s: redactJSONText = %q, %v: the credential survived", name, got, changed)
		}
	}
	got, _ := redactJSONText(policy)
	if !strings.Contains(got, `"grants"`) || !strings.Contains(got, `"dst":["*"]`) || !strings.Contains(got, `"token":"[removed]"`) {
		t.Errorf("the rest of the policy changed: %s", got)
	}
	// Nothing to remove: the text comes back untouched, comments and commas included.
	for name, in := range map[string]string{
		"comments and a trailing comma": "{\n  // who may reach what\n  \"grants\": [{\"src\": [\"*\"],}], /* kept */\n}\n",
		"one line":                      `{ /* c */ "a" : 1 , }`,
		"padded":                        " \n[1, 2, // two\n]\n ",
		"false and null stay": `{"token": true, "secret": null, // c
		}`,
		"words with the key's name": `{"note": "the word token in a comment-free string",}`,
	} {
		if got, changed := redactJSONText(in); changed || got != in {
			t.Errorf("%s: redactJSONText(%q) = %q, %v: text with nothing to remove must come back as it was", name, in, got, changed)
		}
	}
	// Neither JSON nor HuJSON: as it is.
	for _, in := range []string{
		"token=PLANTED&n=1", "token: PLANTED\nn: 1", `{"token": "PLANTED"`, `{"a": 1} {"token": "PLANTED"}`, `{"token": "PLANTED",,}`,
		"{'token': 'PLANTED'}", `{token: "PLANTED"}`, "[1, 2", "/* only a comment */", `"unclosed`,
	} {
		if got, changed := redactJSONText(in); changed || got != in {
			t.Errorf("redactJSONText(%q) = %q, %v: text that is neither JSON nor HuJSON stays as it is", in, got, changed)
		}
	}
}

// A policy file often opens with a comment ("// policy" or a block comment before the
// brace), and a file may start with a byte order mark: the text is HuJSON all the same,
// and the credential-named values in it are removed. With nothing to remove the text
// comes back as it came, the comment and the byte order mark included.
func TestRedactJSONTextReadsHuJSONBehindACommentOrAByteOrderMark(t *testing.T) {
	const bom = "\ufeff"
	body := `{"groups": {"group:a": ["x"],}, "token": "PLANTED-HU",}`
	clean := `{"groups": {"group:a": ["x"],}, "n": 1.50,}`
	for name, lead := range map[string]string{
		"a line comment":               "// policy\n",
		"a line comment, CRLF":         "// policy\r\n",
		"a block comment":              "/* policy */ ",
		"a block comment over lines":   "/* policy\n   of the tailnet */\n",
		"two comments":                 "// one\n/* two */\n// three\n",
		"a byte order mark":            bom,
		"a byte order mark and spaces": bom + "  \n",
		"a byte order mark, a comment": bom + "// policy\n",
		"spaces, then a comment":       "  \n\t// policy\n",
		"a comment that names a token": "// the token below is rotated\n",
		"a block comment with a brace": "/* { */ ",
	} {
		got, changed := redactJSONText(lead + body)
		if !changed || strings.Contains(got, "PLANTED") || !strings.Contains(got, `"groups"`) || !strings.Contains(got, `"token":"[removed]"`) {
			t.Errorf("%s: redactJSONText = %q, %v: the credential survived or the rest changed", name, got, changed)
		}
		// With nothing to remove: byte for byte.
		if got, changed := redactJSONText(lead + clean); changed || got != lead+clean {
			t.Errorf("%s: redactJSONText(%q) = %q, %v: text with nothing to remove must come back as it was", name, lead+clean, got, changed)
		}
		// The same in a string, in an array, and two strings deep.
		nested := `{"policy":` + quoteJSON(lead+body) + `}`
		if got, changed := redactJSONText(nested); !changed || strings.Contains(got, "PLANTED") {
			t.Errorf("%s: a policy in a string: %q, %v", name, got, changed)
		}
		deep := quoteJSON(quoteJSON(lead + body))
		if got, changed := redactJSONText(deep); !changed || strings.Contains(got, "PLANTED") {
			t.Errorf("%s: a policy in a string in a string: %q, %v", name, got, changed)
		}
		if got, changed := redactJSONText("[" + quoteJSON(lead+body) + "]"); !changed || strings.Contains(got, "PLANTED") {
			t.Errorf("%s: a policy in an array: %q, %v", name, got, changed)
		}
	}
	// A comment after the document too: a line comment that ends the text with no line
	// feed, one with, and a block comment.
	for name, trail := range map[string]string{
		"a trailing line comment, no line feed": " // end",
		"a trailing line comment":               "\n// end\n",
		"a trailing line comment, CRLF":         "\r\n// end\r\n",
		"a trailing block comment":              " /* end */",
		"white space":                           " \n\t",
		"comments on both sides":                " // one\n/* two */",
	} {
		for _, lead := range []string{"", "// policy\n", bom} {
			if got, changed := redactJSONText(lead + body + trail); !changed || strings.Contains(got, "PLANTED") {
				t.Errorf("%s after %q: redactJSONText = %q, %v: the credential survived", name, lead, got, changed)
			}
			if got, changed := redactJSONText(lead + clean + trail); changed || got != lead+clean+trail {
				t.Errorf("%s after %q: %q came back as %q, %v: text with nothing to remove must come back as it was", name, lead, lead+clean+trail, got, changed)
			}
		}
	}
	// Strict JSON behind a byte order mark, and an array.
	for _, in := range []string{bom + `{"token":"PLANTED-HU"}`, "// c\n" + `["a", {"secret": "PLANTED-HU"}]`, bom + "/* c */" + `"{\"password\": \"PLANTED-HU\"}"`} {
		if got, changed := redactJSONText(in); !changed || strings.Contains(got, "PLANTED") {
			t.Errorf("redactJSONText(%q) = %q, %v", in, got, changed)
		}
	}
	// Neither JSON nor HuJSON, whatever comes before: as it is.
	for _, in := range []string{
		"// policy\ntoken=PLANTED&n=1", "/* policy */ token: PLANTED", "// only a comment", "/* only a comment */", bom, bom + "token=PLANTED",
		"/* unterminated {\"token\": \"PLANTED\"}", "// policy\n" + `{"token": "PLANTED"`, "// policy\n" + `{"token": "PLANTED"} {"a": 1}`, bom + `{"token": "PLANTED",,}`,
		"/ policy\n" + body, "# policy\n" + body, "x " + body, "12 " + body, "true " + body,
	} {
		if got, changed := redactJSONText(in); changed || got != in {
			t.Errorf("redactJSONText(%q) = %q, %v: text that is neither JSON nor HuJSON stays as it is", in, got, changed)
		}
	}
	// Numbers and words are no documents, at any depth.
	for _, in := range []string{"12", "true", " null ", "// c\n12", quoteJSON("12"), quoteJSON(" true "), `/* " */ 12`, quoteJSON(quoteJSON(quoteJSON(`/* " */ 12`)))} {
		if got, changed := redactJSONText(in); changed || got != in {
			t.Errorf("redactJSONText(%q) = %q, %v", in, got, changed)
		}
	}
}

// Reading comments and a byte order mark in front of a document is linear: a lot of
// them, one comment that never ends, and text that only looks like a start.
func TestRedactJSONTextIsLinear(t *testing.T) {
	const n = 256 << 10
	doc := `{"token": "PLANTED", "a": [1, 2,],}`
	for name, s := range map[string]string{
		"line comments":            strings.Repeat("// c\n", n/5) + doc,
		"block comments":           strings.Repeat("/* c */", n/7) + doc,
		"byte order marks":         strings.Repeat("\ufeff", n/3) + doc,
		"white space":              strings.Repeat(" \n\t", n/3) + doc,
		"a block comment, no end":  "/*" + strings.Repeat("a", n) + doc,
		"a line comment, no end":   "//" + strings.Repeat("a", n) + doc,
		"brackets":                 strings.Repeat("[", n),
		"objects, no end":          strings.Repeat(`{"a":`, n/5),
		"a string, no end":         `"` + strings.Repeat("a", n),
		"quoted words":             strings.Repeat(`"a" `, n/4),
		"a document and more":      strings.Repeat(doc+" ", n/len(doc)),
		"a comment, then a string": "// c\n" + quoteJSON(strings.Repeat("a", n)),
		"strings in strings":       quoteJSON(quoteJSON(quoteJSON(strings.Repeat("// c\n", n/15) + doc))),
	} {
		start := time.Now()
		redactJSONText(s)
		if d := time.Since(start); d > 3*time.Second {
			t.Errorf("%s: %s for %d bytes", name, d, len(s))
		}
	}
}

// The HuJSON reader recurses once per level of nesting and cannot be stopped when the
// stack runs out (a fatal error, not a panic), so text that nests deeper than any
// policy does is not given to it: it is removed whole, as the top level removes text it
// cannot read. Deep strict JSON never reaches the reader, and a document that is deep
// but not past the bound is read and redacted as before.
func TestRedactJSONTextRemovesWhatNestsTooDeepForHuJSON(t *testing.T) {
	const bom = "\xef\xbb\xbf"
	deep := func(n int) string { return strings.Repeat("[", n-1) + "[1,]" + strings.Repeat("]", n-1) } // n levels, HuJSON
	for name, in := range map[string]string{
		"2,000,000 brackets":                strings.Repeat("[", 2_000_000),
		"1,000,000 objects":                 strings.Repeat(`{"a":`, 1_000_000),
		"1,000,000 brackets, then as many":  strings.Repeat("[", 1_000_000) + strings.Repeat("]", 1_000_000),
		"brackets behind a comment":         "// policy\n" + strings.Repeat("[", 1_000_000),
		"brackets behind a byte order mark": bom + strings.Repeat("[", 1_000_000),
		"braces and brackets":               strings.Repeat(`{"a":[`, 500_000),
		"1,001 levels":                      deep(1001),
		"1,001 levels with a credential":    strings.Repeat("[", 1000) + `{"token":"PLANTED",}` + strings.Repeat("]", 1000),
		"deep, with a comment in between":   strings.Repeat("[/* c */", 1500) + "1,",
		// A comment that ends right where another begins: the scan resumes on the byte after
		// the "*/" of the first, and a scan that resumes on its "/" reads a line comment.
		"two block comments in a row":          "/* a *//* b */" + strings.Repeat("[", 5000),
		"a block comment, then a line comment": "/* a */// b\n" + strings.Repeat("[", 5000),
		"a block comment, then a slash":        "/* a */ / " + strings.Repeat("[", 5000),
		"three block comments in a row":        "/**//**//**/" + strings.Repeat("[", 5000),
		"a string that holds a deep document":  quoteJSON(strings.Repeat("[", 1_500_000)),
	} {
		got, changed := redactJSONText(in)
		if !changed || got != removedValue && !strings.HasPrefix(got, `"`) {
			t.Errorf("%s: redactJSONText = %.60q, %v: want the value removed", name, got, changed)
		}
		if strings.Contains(got, "PLANTED") {
			t.Errorf("%s: the credential survived", name)
		}
	}
	// Up to the bound a document is read: its credential goes, the rest stays.
	for name, in := range map[string]string{
		"1,000 levels":                     deep(1000),
		"999 levels with a credential":     strings.Repeat("[", 998) + `{"token":"PLANTED",}` + strings.Repeat("]", 998),
		"1,000 levels with a credential":   strings.Repeat("[", 999) + `{"token":"PLANTED",}` + strings.Repeat("]", 999),
		"a comment holding brackets":       "/* " + strings.Repeat("[", 5000) + " */ " + `{"token":"PLANTED",}`,
		"a line comment holding brackets":  "// " + strings.Repeat("[", 5000) + "\n" + `{"token":"PLANTED",}`,
		"a line comment after the text":    `{"token":"PLANTED",}` + "\n// " + strings.Repeat("{[", 2500),
		"a line comment between values":    `{"a": // ` + strings.Repeat("[", 5000) + "\n 1, \"token\": \"PLANTED\",}",
		"a string holding brackets":        `{"a": "` + strings.Repeat("[", 5000) + `", "token": "PLANTED",}`,
		"brackets that close again":        strings.Repeat("[1,],", 5000) + "",
		"escaped quotes before brackets":   `{"a": "\"` + strings.Repeat("[", 5000) + `", "token": "PLANTED",}`,
		"a line comment with an odd quote": "// it's \"quoted\n" + `{"token":"PLANTED",}`,
	} {
		got, changed := redactJSONText(in)
		if strings.Contains(got, "PLANTED") {
			t.Errorf("%s: the credential survived: %.80q", name, got)
		}
		if name == "1,000 levels" || name == "brackets that close again" {
			if changed || got != in {
				t.Errorf("%s: nothing to remove, but redactJSONText = %.60q, %v", name, got, changed)
			}
			continue
		}
		if !changed || got == removedValue {
			t.Errorf("%s: redactJSONText = %.60q, %v: want the credential removed and the rest read", name, got, changed)
		}
	}
	// Strict JSON deeper than the bound is read by encoding/json (which has its own limit,
	// 10,000) and redacted, not removed.
	strict := strings.Repeat("[", 5000) + `{"token":"PLANTED"}` + strings.Repeat("]", 5000)
	if got, changed := redactJSONText(strict); !changed || strings.Contains(got, "PLANTED") || got == removedValue {
		t.Errorf("5,000 levels of strict JSON: %.60q, %v", got, changed)
	}
}

// HuJSON deeper than the nesting the redaction reads is removed whole, as JSON is.
func TestRedactJSONTextRemovesHuJSONBeyondTheDepthItReads(t *testing.T) {
	doc := "{\"a\": 1, // c\n}"
	for range maxNesting {
		doc = quoteJSON(doc)
	}
	if got, changed := redactJSONText(doc); !changed || strings.Contains(got, `"a"`) {
		t.Errorf("redactJSONText = %q, %v: HuJSON below the depth read must be removed", got, changed)
	}
}

func quoteJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// A key repeated in one object: Go keeps the last value, so the API's text, handed
// back as it was, would still hold the first, and the first can be the credential.
func TestRedactSecretsRemovesTheEarlierValueOfARepeatedKey(t *testing.T) {
	for _, raw := range []string{
		`{"token":"PLANTED-DUP-1","token":true}`,
		`{"token":"PLANTED-DUP-2","token":null}`,
		`{"token":"PLANTED-DUP-3","token":false,"name":"x"}`,
		`{"a":{"x":1,"secret":"PLANTED-DUP-4","secret":false}}`,
		`[{"token":"PLANTED-DUP-5","token":null}]`,
		`{"token":"PLANTED-DUP-6","tok\u0065n":true}`,
		`{"policy":` + quoteJSON(`{"token":"PLANTED-DUP-7","token":true}`) + `}`,
		`{"a":{"token":"PLANTED-DUP-8"},"b":[{"x":1,"x":2,"password":"PLANTED-DUP-9","password":true}]}`,
		`{"a":[{"k":1},{"token":"PLANTED-DUP-10","token":null}],"k":3}`,
	} {
		got := string(redactSecrets(json.RawMessage(raw)))
		if strings.Contains(got, "PLANTED") {
			t.Errorf("redactSecrets(%s) = %s: the earlier value of a repeated key survived", raw, got)
		}
		if !json.Valid([]byte(got)) {
			t.Errorf("redactSecrets(%s) = %s: not JSON", raw, got)
		}
	}
	// A repeated key that is no credential is not kept twice either: the text is
	// written again, with the value Go keeps.
	if got := string(redactSecrets(json.RawMessage(`{"name":"first","name":"last"}`))); got != `{"name":"last"}` {
		t.Errorf("repeated plain key: %s", got)
	}
	// The same key in different objects, in an array, or beside a nested one is
	// no repeat: the text comes back as it was.
	for _, same := range []string{`{"a":{"x":1},"b":{"x":2}}`, `[{"x":1},{"x":2}]`, `{"a":[{"k":1},{"k":2}],"k":3}`,
		`{"a":{"k":1},"k":{"k":2}}`, `{ "token": true , "n": {"token":null} }`, `{"a":[[{"x":1}],[{"x":2}]]}`} {
		if got := string(redactSecrets(json.RawMessage(same))); got != same {
			t.Errorf("no key is repeated in %s, yet it came back as %s", same, got)
		}
	}
	// Inside a string that holds JSON, as the nested object above.
	if text, changed := redactJSONText(`{"token":"PLANTED-DUP-11","token":true}`); !changed || strings.Contains(text, "PLANTED") {
		t.Errorf("redactJSONText kept the earlier value: %q, %v", text, changed)
	}
}

// buried is a document that holds doc n strings down: each layer is a string that
// holds the next.
func buried(doc string, n int) string {
	for i := 0; i < n; i++ {
		doc = `{"k":` + quoteJSON(doc) + `}`
	}
	return doc
}

// A string can hold a JSON string that holds a document, and so on; three strings
// deep are read. What lies deeper is removed whole, since it cannot be searched.
func TestRedactSecretsReadsStringsInsideStringsToAPoint(t *testing.T) {
	// A string whose content is a JSON string, which holds an object.
	doubled := `{"policy":"\"{\\\"apiKey\\\":\\\"PLANTED-S7\\\"}\""}`
	got := string(redactSecrets(json.RawMessage(doubled)))
	if strings.Contains(got, "PLANTED") || !json.Valid([]byte(got)) {
		t.Fatalf("a double-encoded document kept its credential: %s", got)
	}
	var doc struct{ Policy string }
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatal(err)
	}
	var inner string
	if err := json.Unmarshal([]byte(doc.Policy), &inner); err != nil || inner != `{"apiKey":"[removed]"}` {
		t.Errorf("the layers should stay as they were, with the value removed: policy = %q, inner = %q, %v", doc.Policy, inner, err)
	}
	// With nothing to remove, the API's text comes back as it was.
	plain := `{"policy":"\"{\\\"a\\\":1}\"","other":"\"just a quoted word\""}`
	if got := string(redactSecrets(json.RawMessage(plain))); got != plain {
		t.Errorf("nothing was removed, so the text must be unchanged: %s", got)
	}
	// The same, as the content of a top-level string.
	if text, changed := redactJSONText(`"{\"apiKey\":\"PLANTED-TOP\"}"`); !changed || strings.Contains(text, "PLANTED") {
		t.Errorf("redactJSONText(a JSON string) = %q, %v", text, changed)
	}
	// Three strings deep: read, and the rest of the document kept.
	secret := `{"token":"PLANTED-DEEP","keep":"kept"}`
	three := string(redactSecrets(json.RawMessage(buried(secret, 3))))
	if strings.Contains(three, "PLANTED") || !strings.Contains(three, "kept") {
		t.Errorf("three strings deep: %s", three)
	}
	// Deeper: removed whole, however deep.
	for _, n := range []int{4, 5, 12} {
		deep := string(redactSecrets(json.RawMessage(buried(secret, n))))
		if strings.Contains(deep, "PLANTED") || !strings.Contains(deep, "[removed]") {
			t.Errorf("%d strings deep: %s", n, deep)
		}
	}
	// Within the depth that is read, text with nothing to remove stays as it was.
	if text := buried(`just text`, 3); string(redactSecrets(json.RawMessage(text))) != text {
		t.Errorf("text with no credential in it changed: %s", redactSecrets(json.RawMessage(text)))
	}
}

// The depth limit fails closed: JSON held more than maxNesting strings down is
// not searched, so it is removed whole, even when it holds no credential-named key
// at all. The case above plants a credential, which the search would remove at any
// depth if there were no limit, so it cannot tell a limit from none. This one
// plants nothing: only the limit turns the document into [removed], and only a
// limit of exactly maxNesting leaves the shallower ones as they were. The strings
// around the document stay (see the case above), so the result is read through
// them.
func TestRedactSecretsRemovesBenignJSONBeyondTheDepthItReads(t *testing.T) {
	benign := `{"name":"keep me","n":1}`
	if secretKeyRE.MatchString(benign) {
		t.Fatalf("the document must hold no credential-named key: %s", benign)
	}
	// quoted wraps doc in n layers of JSON string quoting: n strings hold it.
	quoted := func(doc string, n int) string {
		for i := 0; i < n; i++ {
			doc = quoteJSON(doc)
		}
		return doc
	}
	// peeled reads s through every JSON string around it and returns what is
	// inside: the document, or [removed], which is not JSON.
	peeled := func(s string) string {
		for {
			var inner string
			if json.Unmarshal([]byte(s), &inner) != nil {
				return s
			}
			s = inner
		}
	}
	// The preview of an old or new value that is a string.
	for _, n := range []int{4, 5, 12} {
		got := previewText(json.RawMessage(quoted(benign, n)))
		if peeled(got) != removedValue || strings.Contains(got, "keep me") {
			t.Errorf("previewText of a document %d strings deep, read through its strings, = %q, want %s", n, peeled(got), removedValue)
		}
	}
	// Three strings deep are read, and a document with nothing to remove comes back
	// as the API sent it.
	if got, want := previewText(json.RawMessage(quoted(benign, 3))), quoted(benign, 2); got != want || peeled(got) != benign {
		t.Errorf("previewText of a document 3 strings deep = %q, want it unchanged: %q", got, want)
	}
	// The same through an object whose string holds the document.
	if got := string(redactSecrets(json.RawMessage(buried(benign, 4)))); !strings.Contains(got, removedValue) || strings.Contains(got, "keep me") {
		t.Errorf("redactSecrets of a document 4 strings deep = %s, want it replaced by %s", got, removedValue)
	}
	if same := buried(benign, 3); string(redactSecrets(json.RawMessage(same))) != same {
		t.Errorf("redactSecrets of a document 3 strings deep changed it: %s", redactSecrets(json.RawMessage(same)))
	}
}
