package apitest

import "net/http"

// Serve registers s as the answer to method and path.
func (f *Fake) Serve(method, path string, s Shape) {
	f.Raw(method, path, s.Status, s.Body, s.Header)
}

// ServeValidate registers s as the answer to POST .../acl/validate.
func (f *Fake) ServeValidate(s Shape) {
	f.t.Helper()
	if s.Endpoint != EndpointValidate {
		f.t.Fatalf("%s answers %s, not the validate endpoint", s.Name, s.Endpoint)
	}
	f.Serve("POST", ValidatePath, s)
}

// aclPath is GET .../acl, the policy.
const aclPath = "/api/v2/tailnet/" + Tailnet + "/acl"

// ServePolicy registers s as the answer to GET .../acl without details. A request
// that asks for details=true fails the test: it would be answered with a plain policy
// where the caller expects JSON.
func (f *Fake) ServePolicy(s Shape) {
	f.t.Helper()
	if s.Endpoint != EndpointPolicy {
		f.t.Fatalf("%s answers %s, not the policy endpoint", s.Name, s.Endpoint)
	}
	f.Handle("GET", aclPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("details") {
			f.t.Errorf("a plain policy read carried details=%q; the shape %s is the plain text", r.URL.Query().Get("details"), s.Name)
		}
		s.Write(w)
	})
}

// ServeDetails registers s as the answer to GET .../acl?details=true. A request
// without details=true fails the test: the answer is the JSON object, not the policy.
func (f *Fake) ServeDetails(s Shape) {
	f.t.Helper()
	if s.Endpoint != EndpointPolicy {
		f.t.Fatalf("%s answers %s, not the policy endpoint", s.Name, s.Endpoint)
	}
	f.Handle("GET", aclPath, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("details") != "true" {
			f.t.Errorf("a details read must carry details=true, got %q", r.URL.Query().Get("details"))
		}
		s.Write(w)
	})
}

// Write answers a request with s: its headers, its status and its body. A handler that
// chooses its answer per request (a model of the API) uses it; a test that serves one
// answer uses Serve.
func (s Shape) Write(w http.ResponseWriter) {
	for k, v := range s.Header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(s.Status)
	_, _ = w.Write([]byte(s.Body))
}
