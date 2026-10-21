package api

import "testing"

// readsAsPass says whether a caller that ignored the error of parseValidationBody would
// take the answer for a pass: both readers treat these two shapes as one.
func readsAsPass(s bodyShape) bool { return s == shapeBlank || s == shapeObject }

// parseValidationBody returns no shape that reads as a pass beside an error: the readers
// check the error first, but the function that decides what a pass is must not fail open
// for a caller that does not.
func TestAParseErrorCarriesAShapeThatIsNoPass(t *testing.T) {
	for name, body := range map[string]string{
		"not an object":              `[]`,
		"a key outside the schema":   `{"error":"x"}`,
		"a key twice":                `{"data":[],"data":[]}`,
		"a bad message":              `{"message":5}`,
		"a bad data":                 `{"data":5}`,
		"an entry that is no object": `{"data":[5]}`,
		"an entry with a bad field":  `{"data":[{"user":5,"errors":["e"]}]}`,
		"an entry with nothing":      `{"data":[{"user":"u"}]}`,
		"trailing bytes":             `{} x`,
	} {
		message, results, shape, err := parseValidationBody([]byte(body))
		if err == nil {
			t.Errorf("%s: no error for %q", name, body)
			continue
		}
		if readsAsPass(shape) || message != "" || results != nil {
			t.Errorf("%s: shape %d, message %q, results %v beside the error %v; want a shape that is no pass and nothing else", name, shape, message, results, err)
		}
	}
	// The zero value is the shape that is no pass, so that a shape nothing set fails closed.
	var zero bodyShape
	if zero != shapeInvalid || readsAsPass(zero) {
		t.Errorf("the zero bodyShape is %d, want shapeInvalid (%d)", zero, shapeInvalid)
	}
}
