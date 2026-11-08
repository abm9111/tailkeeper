package tools

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/registry"
	"github.com/abm9111/tailkeeper/internal/safefile"
	"github.com/abm9111/tailkeeper/internal/security"
	"github.com/abm9111/tailkeeper/internal/securitypack"
	"github.com/abm9111/tailkeeper/internal/tkerr"
)

// SecurityExportInput selects the sources captured in an owner-only pack.
type SecurityExportInput struct {
	Scope        string   `json:"scope" tk:"short" jsonschema:"fleet or local"`
	Access       bool     `json:"access,omitempty" jsonschema:"capture selected access evidence"`
	Only         []string `json:"only,omitempty" tk:"short" jsonschema:"expectation IDs"`
	Out          string   `json:"out,omitempty" tk:"short" jsonschema:"private output path"`
	Invariants   string   `json:"-" cli:"file:invariants"`
	NoInvariants bool     `json:"-" cli:"bool:no-invariants"`
	Operator     bool     `json:"-" cli:"operator"`
}

func (in SecurityExportInput) Check() error {
	if err := (SecurityScanInput{Scope: in.Scope}).Check(); err != nil {
		return err
	}
	if in.Out == "-" {
		return validationf("pack output cannot be standard output")
	}
	if len(in.Only) > 0 && !in.Access {
		return validationf("--only requires --access")
	}
	_, err := (SecurityExplainInput{Only: in.Only}).onlyIDs()
	return err
}
func (in SecurityExportInput) RunsOffline(registry.Given) bool {
	return in.Scope == scanLocal && !in.Access
}

type PackScanSummary struct {
	Status          string             `json:"status"`
	EvaluatedAt     string             `json:"evaluatedAt"`
	Counts          SecurityScanCounts `json:"counts"`
	CatalogRevision uint64             `json:"catalogRevision"`
	CatalogRules    int                `json:"catalogRules"`
}
type PackAccessSummary struct {
	Status string                `json:"status"`
	Counts SecurityExplainCounts `json:"counts"`
}

// SecurityPackSummary reports metadata only, never the pack contents.
type SecurityPackSummary struct {
	Path      string             `json:"path,omitempty" tk:"untrusted,emails"`
	Bytes     int64              `json:"bytes,omitempty"`
	Ref       string             `json:"ref,omitempty"`
	Seal      string             `json:"seal,omitempty"`
	Outcome   string             `json:"outcome"`
	Scope     string             `json:"scope,omitempty"`
	Findings  int64              `json:"findings,omitempty"`
	Statement string             `json:"statement,omitempty"`
	Pack      string             `json:"pack"`
	Scan      *PackScanSummary   `json:"scan,omitempty"`
	Access    *PackAccessSummary `json:"access,omitempty"`
}

func (o SecurityPackSummary) ExitCode() int {
	if o.Outcome != "reproduced" {
		return 1
	}
	return 0
}
func (o SecurityPackSummary) AuditFields() map[string]any {
	return map[string]any{"pack": o.Pack, "seal": o.Seal, "outcome": o.Outcome, "digest": o.Ref, "bytes": o.Bytes, "findings": o.Findings}
}

func SecurityExportTool() registry.Tool {
	m := readMeta("security_export", "security", "export", "Capture a private reproducible evidence pack; owner command line only.", aclScopes...)
	m.Credential = registry.CredOptional
	m.Operations = []string{"GET /tailnet/{tailnet}/devices", "GET /tailnet/{tailnet}/acl", "POST /tailnet/{tailnet}/acl/validate"}
	m.Title, m.OpenWorld = "Export security evidence", true
	return registry.Define(m, securityExport)
}
func packSealer(env *registry.Env) securitypack.Sealer {
	if env != nil && env.Privacy != nil {
		return env.Privacy.Digest
	}
	return nil
}
func packPrivacyError(env *registry.Env) error {
	if env != nil && env.PrivacyErr != nil {
		return env.PrivacyErr
	}
	return nil
}
func packPlatform() error {
	if runtime.GOOS == "windows" {
		return tkerr.New(tkerr.UnsupportedTarget, "private evidence files are unsupported on Windows", "")
	}
	return nil
}
func packOutputPath(env *registry.Env, path, prefix string) (string, error) {
	if path == "-" {
		return "", validationf("pack output cannot be standard output")
	}
	if path != "" {
		return path, nil
	}
	if env == nil || env.Config == nil || env.Config.Dirs.State == "" {
		return "", tkerr.New(tkerr.ConfigInvalid, "the state directory is unavailable", "")
	}
	dir := filepath.Join(env.Config.Dirs.State, "packs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", tkerr.New(tkerr.ConfigInvalid, "cannot create the private packs directory", "")
	}
	return filepath.Join(dir, prefix+env.Clock().UTC().Format("20060102T150405Z")+".json"), nil
}
func packRef(data []byte, env *registry.Env) (string, securitypack.Reading, error) {
	p, reading, err := securitypack.Decode(data, packSealer(env))
	if err != nil {
		return "", reading, err
	}
	ref, err := securitypack.Reference(p, packSealer(env), env.ShowPersonalData())
	return ref, reading, err
}
func packSealWord(s securitypack.SealState) string {
	if s == securitypack.SealValid {
		return "keyed"
	}
	return string(s)
}
func packWriteError(err error, defaultPath bool) error {
	if e, ok := tkerr.As(err); ok && e.Code == tkerr.AuditUnavailable {
		return err
	}
	if defaultPath {
		return err
	}
	return tkerr.New(tkerr.ValidationFailed, "the private output path was refused", "")
}
func packCodecError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return scanError(err, "evidence processing was interrupted")
	}
	if errors.Is(err, securitypack.ErrStoppedEarly) || errors.Is(err, securitypack.ErrNotReproduced) {
		return tkerr.New(tkerr.APIError, "the evidence did not reproduce; no file was written", "")
	}
	return tkerr.New(tkerr.ValidationFailed, "the evidence pack was refused", "")
}
func exportAccess(ctx context.Context, env *registry.Env, in SecurityExportInput, set *security.IntentSet) (*securitypack.AccessEvidence, error) {
	if !in.Access {
		return nil, nil
	}
	if set == nil {
		return nil, validationf("--access requires an intent set")
	}
	only, err := (SecurityExplainInput{Only: in.Only}).onlyIDs()
	if err != nil {
		return nil, err
	}
	selected, err := selectIntent(*set, only)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(selected.Network)+len(selected.SSH))
	for _, e := range selected.Network {
		ids = append(ids, e.ID)
	}
	for _, e := range selected.SSH {
		ids = append(ids, e.ID)
	}
	ref, err := apiContextRef(env)
	if err != nil {
		return nil, err
	}
	input, _, err := collectAccessInput(ctx, env, selected)
	if err != nil {
		return nil, err
	}
	return &securitypack.AccessEvidence{Context: ref, Selected: ids, Input: input}, nil
}
func packExportPreflight(env *registry.Env, in SecurityExportInput) error {
	if err := packPlatform(); err != nil {
		return err
	}
	if err := packPrivacyError(env); err != nil {
		return err
	}
	if env == nil || env.RecordPack == nil {
		return tkerr.New(tkerr.AuditUnavailable, "pack audit recording is unavailable", "")
	}
	if in.Scope == scanFleet || in.Access {
		_, err := env.RequireAPI()
		return err
	}
	return nil
}
func securityExport(ctx context.Context, env *registry.Env, in SecurityExportInput) (SecurityPackSummary, error) {
	if err := packExportPreflight(env, in); err != nil {
		return SecurityPackSummary{}, err
	}
	sources, err := advisory.ShippedSources()
	if err != nil {
		return SecurityPackSummary{}, tkerr.New(tkerr.Internal, "the shipped advisory catalog cannot be read", "")
	}
	catalog, err := advisory.Merge(sources)
	if err != nil {
		return SecurityPackSummary{}, tkerr.New(tkerr.Internal, "the shipped advisory catalog cannot be merged", "")
	}
	scan := SecurityScanInput{Scope: in.Scope, Invariants: in.Invariants, NoInvariants: in.NoInvariants, Operator: in.Operator}
	run, err := runScanInputs(ctx, env, scan, func() (security.Catalog, error) { return catalog, nil })
	if err != nil {
		return SecurityPackSummary{}, err
	}
	access, err := exportAccess(ctx, env, in, run.Input.Intent)
	if err != nil {
		return SecurityPackSummary{}, err
	}
	data, replayed, err := securitypack.Build(ctx, securitypack.BuildInput{Input: run.Input, Report: run.Report, Sources: sources, Access: access}, packSealer(env))
	if err != nil {
		return SecurityPackSummary{}, packCodecError(err)
	}
	ref, reading, err := packRef(data, env)
	if err != nil {
		return SecurityPackSummary{}, packCodecError(err)
	}
	path, err := packOutputPath(env, in.Out, "tailkeeper-pack-"+in.Scope+"-")
	if err != nil {
		return SecurityPackSummary{}, err
	}
	size, findings := int64(len(data)), int64(replayed.Report.TotalFindings)
	record := registry.PackRecord{Pack: "export", Seal: packSealWord(reading.Seal), Outcome: "reproduced", Digest: ref, Bytes: &size, Findings: &findings}
	if err := safefile.WritePrivate(path, data, func() error { return env.RecordPack(ctx, record) }); err != nil {
		return SecurityPackSummary{}, packWriteError(err, in.Out == "")
	}
	summary := SecurityPackSummary{Path: path, Bytes: size, Ref: ref, Seal: record.Seal, Outcome: "reproduced", Scope: in.Scope, Findings: findings, Pack: "export", Statement: "Export is evidence capture; the pack was written and reproduces.", Scan: &PackScanSummary{Status: string(replayed.Report.Status), EvaluatedAt: timeText(replayed.Report.GeneratedAt), Counts: countFindings(replayed.Report.Findings), CatalogRevision: catalog.Revision, CatalogRules: len(catalog.Records)}}
	if replayed.AccessReport != nil {
		summary.Access = &PackAccessSummary{Status: string(replayed.AccessReport.Status), Counts: SecurityExplainCounts(replayed.AccessReport.Counts)}
	}
	return summary, nil
}
