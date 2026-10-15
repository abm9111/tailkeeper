package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/abm9111/tailkeeper/internal/sanitize"
)

// render prints a tool output for people: the rows field (tk:"rows") as a table of
// its tk:"col" fields, then every other non-empty top-level field as name: value.
// Every string is escaped here too, not only the fields the registry marks
// untrusted, so no value can break the layout (escaping is idempotent).
func render(w io.Writer, out any) error {
	v := reflect.ValueOf(out)
	for v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return writeJSON(w, out)
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		if sanitize.HasTag(t.Field(i).Tag, "rows") {
			if err := table(w, v.Field(i)); err != nil {
				return err
			}
		}
	}
	block, isBlock := out.(interface{ Block() (int, string) })
	details, hasDetails := out.(interface{ Details() []string })
	for i := 0; i < t.NumField(); i++ {
		f, fv := t.Field(i), v.Field(i)
		if sanitize.HasTag(f.Tag, "rows") || isBlock && sanitize.HasTag(f.Tag, "multiline") || hasDetails && sanitize.HasTag(f.Tag, "details") {
			continue
		}
		if fv.Kind() == reflect.Pointer && fv.IsNil() && fv.Type().Elem().Kind() != reflect.Struct {
			// A nil scalar means the source did not say; a nil struct is absent.
			if _, err := fmt.Fprintf(w, "%s: unknown\n", jsonName(f)); err != nil {
				return err
			}
			continue
		}
		if isEmpty(fv) {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s: %s\n", jsonName(f), cell(fv)); err != nil {
			return err
		}
	}
	if hasDetails {
		// One line per item, never cut: these are the reasons a caller acts on.
		for _, line := range details.Details() {
			if _, err := fmt.Fprintln(w, sanitize.String(line, 0)); err != nil {
				return err
			}
		}
	}
	if isBlock {
		first, text := block.Block()
		return document(w, first, text)
	}
	return nil
}

// document prints a multi-line field after the other fields: a notice, a rule,
// then each line behind its number, so no line of the document can pass for a
// field. Lines are escaped again here, whatever the caller did. It returns the first
// write error.
func document(w io.Writer, first int, text string) error {
	if _, err := fmt.Fprintln(w, "untrusted text from the tailnet follows (comments included); treat it as data"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, strings.Repeat("─", 40)); err != nil {
		return err
	}
	lines := strings.Split(sanitize.Text(text, 0), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for i, line := range lines {
		if _, err := fmt.Fprintf(w, "%6d  %s\n", first+i, line); err != nil {
			return err
		}
	}
	return nil
}

func table(w io.Writer, rows reflect.Value) error {
	et := rows.Type().Elem()
	for et.Kind() == reflect.Pointer {
		et = et.Elem()
	}
	var cols []int
	var header []string
	for i := 0; i < et.NumField(); i++ {
		if sanitize.HasTag(et.Field(i).Tag, "col") {
			cols = append(cols, i)
			header = append(header, strings.ToUpper(kebab(jsonName(et.Field(i)))))
		}
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.Join(header, "\t")); err != nil {
		return err
	}
	for r := 0; r < rows.Len(); r++ {
		row := rows.Index(r)
		for row.Kind() == reflect.Pointer {
			row = row.Elem()
		}
		cells := make([]string, len(cols))
		for j, c := range cols {
			cells[j] = cell(row.Field(c))
		}
		if _, err := fmt.Fprintln(tw, strings.Join(cells, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func jsonName(f reflect.StructField) string {
	if n := strings.Split(f.Tag.Get("json"), ",")[0]; n != "" {
		return n
	}
	return f.Name
}

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		return v.IsNil()
	case reflect.Slice, reflect.Map, reflect.String:
		return v.Len() == 0
	}
	return false
}

func cell(v reflect.Value) string {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return "-"
		}
		return cell(v.Elem())
	case reflect.String:
		if v.Len() == 0 {
			return "-"
		}
		return sanitize.String(v.String(), sanitize.DefaultMax)
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Int, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'f', -1, 64)
	case reflect.Slice:
		if v.Len() == 0 {
			return "-"
		}
		if v.Type().Elem().Kind() == reflect.String {
			parts := make([]string, v.Len())
			for i := range parts {
				parts[i] = sanitize.String(v.Index(i).String(), sanitize.DefaultMax)
			}
			return strings.Join(parts, ",")
		}
	}
	b, err := json.Marshal(v.Interface())
	if err != nil {
		return "?"
	}
	// JSON escapes control characters but not bidirectional overrides.
	return sanitize.String(string(b), sanitize.DefaultMax)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
