package tools_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The class, not the instances: a text field that names a route, a DERP region or a prefix
// carries what a node advertised or what the tailnet's own text says, so it must be tagged
// untrusted, or a new tool would return it unescaped. A dropped tag is otherwise caught only by
// the generated-docs check, which a regenerate-and-commit satisfies.
func TestEveryRouteAndRegionTextFieldIsTaggedUntrusted(t *testing.T) {
	// A field is a route or region field when its name contains one of these, ignoring case.
	parts := []string{"route", "derp", "region", "prefix", "advertised", "enabled", "latent", "pending"}
	// String fields with such names that hold a word tailkeeper chose, or a setting the API names
	// from a fixed set, not text a node or the tailnet wrote. Each is keyed by tool and path.
	notText := map[string]bool{
		"network_flow_logs loggingEnabled":     true, // true, false or unknown, set by tailkeeper
		"settings_get settings.routeSelection": true, // known gap: an untagged API string, not escaped; tagging it is parked for the owner (tool-list budget)
	}
	// The fields the class is known to reach, so that a walk which stops finding them cannot
	// pass for a class with nothing in it.
	want := []string{
		"device_get advertisedRoutes", "device_get enabledRoutes", "device_get connectivity.preferredDerp",
		"devices_list devices[].advertisedRoutes", "devices_list devices[].enabledRoutes", "devices_list devices[].connectivity.preferredDerp",
		"device_routes advertised", "device_routes enabled", "device_routes pending", "device_routes latent", "device_routes haPeers[].prefix",
		"local_ping replies[].region", "log_streaming_get configuration.s3Region",
	}
	var checked []string
	routeField := func(name string) bool {
		n := strings.ToLower(name)
		for _, p := range parts {
			if strings.Contains(n, p) {
				return true
			}
		}
		return false
	}
	for _, tool := range newRegistry(t).All() {
		var walk func(typ reflect.Type, prefix string, seen map[reflect.Type]bool)
		walk = func(typ reflect.Type, prefix string, seen map[reflect.Type]bool) {
			for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
				if typ.Kind() != reflect.Pointer {
					prefix += "[]"
				}
				typ = typ.Elem()
			}
			if typ.Kind() != reflect.Struct || seen[typ] {
				return
			}
			seen[typ] = true
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				path := name
				if prefix != "" {
					path = prefix + "." + name
				}
				str := f.Type.Kind() == reflect.String || (f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Pointer) && f.Type.Elem().Kind() == reflect.String
				if str && routeField(name) && !notText[tool.Meta.Name+" "+path] {
					checked = append(checked, tool.Meta.Name+" "+path)
					if !slices.Contains(tool.UntrustedFields, path) {
						t.Errorf("%s: output field %s names a route, a region or a prefix and is not tagged untrusted", tool.Meta.Name, path)
					}
				}
				walk(f.Type, path, seen)
			}
		}
		walk(tool.OutputType, "", map[reflect.Type]bool{})
	}
	for _, w := range want {
		if !slices.Contains(checked, w) {
			t.Errorf("the walk did not reach %s: the class test has lost a field it was written for", w)
		}
	}
}
