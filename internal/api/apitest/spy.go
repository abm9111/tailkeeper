package apitest

import (
	"encoding/json"
	"fmt"
	"mime"
)

// validateMismatch says why a validate POST's content type and body disagree, or
// returns "" when they agree. Tests mode is application/json and a JSON array of
// tests; policy mode is application/hujson and the policy object as the exact
// bytes (comments and trailing commas allowed). It checks that the content type and
// the body agree on the mode, not that the bytes are exact: it cannot know the bytes
// the caller meant to send. A later change that sends a policy compares Request.Body with the proposal byte for byte.
func validateMismatch(contentType string, body []byte) string {
	mt, _, err := mime.ParseMediaType(contentType)
	switch {
	case err != nil || (mt != "application/json" && mt != "application/hujson"):
		return fmt.Sprintf("a validate POST carried Content-Type %q: tests mode sends application/json and a JSON array, policy mode sends application/hujson and the policy's exact bytes", contentType)
	case mt == "application/json":
		if firstToken(body) != '[' || !json.Valid(body) {
			return "a validate POST with Content-Type application/json must carry a JSON array of tests; any other body runs in the other mode"
		}
	case firstToken(body) != '{':
		return "a validate POST with Content-Type application/hujson must carry the policy object; an array there runs in tests mode and reads as a pass for a policy that was never validated"
	}
	return ""
}

// firstToken returns the first byte of b that is not JSON white space or part of a
// comment, or 0 when there is none (an empty body, only comments, an unterminated
// comment). A byte order mark is not skipped: it is the first token.
func firstToken(b []byte) byte {
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case c == '/' && i+1 < len(b) && b[i+1] == '/':
			for i < len(b) && b[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(b) && b[i+1] == '*':
			end := -1
			for j := i + 2; j+1 < len(b); j++ {
				if b[j] == '*' && b[j+1] == '/' {
					end = j + 1
					break
				}
			}
			if end < 0 {
				return 0
			}
			i = end
		default:
			return c
		}
	}
	return 0
}
