package securitypack

import (
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/abm9111/tailkeeper/internal/advisory"
	"github.com/abm9111/tailkeeper/internal/security"
)

func expectedCopy(value packExpected) packExpected {
	if value.Access != nil {
		copy := *value.Access
		value.Access = &copy
	}
	return value
}

func sourcesToPack(values []advisory.Source) ([]packSource, error) {
	if len(values) > maxCatalogSources {
		return nil, ErrInvalidPack
	}
	total := 0
	for _, v := range values {
		if len(v.Data) > maxCatalogBytes-total {
			return nil, ErrTooLarge
		}
		total += len(v.Data)
	}
	out := make([]packSource, 0, len(values))
	for _, v := range values {
		digest := sha256.Sum256(v.Data)
		out = append(out, packSource{Name: v.Name, Data: slices.Clone(v.Data), SHA256: fmt.Sprintf("%x", digest)})
	}
	slices.SortFunc(out, func(a, b packSource) int { return stringsCompare(a.Name, b.Name) })
	return out, nil
}

func stringsCompare(a, b string) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func bodyFromInput(in packInput) (packBody, error) {
	if in.EvaluatorVersion != security.EvaluatorVersion {
		return packBody{}, ErrInvalidPack
	}
	if len(in.Snapshot.Versions)+len(in.Snapshot.Platforms)+len(in.Snapshot.Features)+len(in.Snapshot.Policies) > maxSnapshotFacts || len(in.Collected) > 2 {
		return packBody{}, ErrInvalidPack
	}
	if in.Access != nil && len(in.Access.Input.Witnesses) > security.MaxAccessPairs {
		return packBody{}, ErrInvalidPack
	}
	sources, err := sourcesToPack(in.Sources)
	if err != nil {
		return packBody{}, err
	}
	intent, err := intentToPack(in.Intent, in.IntentDigestForm)
	if err != nil {
		return packBody{}, err
	}
	access, err := accessToPack(in.Access, in.Intent)
	if err != nil {
		return packBody{}, err
	}
	return packBody{Access: access, Catalog: packCatalog{Digest: in.CatalogDigest, Sources: sources}, CatalogSchemaVersion: 1, Collected: coverageToPack(in.Collected), Evaluation: packEvaluation{At: in.EvaluationAt.UTC().Round(0), WorkBudget: in.WorkBudget.Candidates}, EvaluatorVersion: in.EvaluatorVersion, Expected: expectedCopy(in.Expected), Format: "tailkeeper-evidence-pack", Intent: intent, PackSchemaVersion: 1, ReportSchemaVersion: 1, Snapshot: snapshotToPack(in.Snapshot)}, nil
}

func bodyToInput(body packBody) (packInput, error) {
	intent, form, err := intentFromPack(body.Intent)
	if err != nil {
		return packInput{}, err
	}
	access, err := accessFromPack(body.Access, intent)
	if err != nil {
		return packInput{}, err
	}
	in := packInput{Snapshot: snapshotFromPack(body.Snapshot), CatalogDigest: body.Catalog.Digest, Collected: coverageFromPack(body.Collected), EvaluationAt: body.Evaluation.At, WorkBudget: security.WorkBudget{Candidates: body.Evaluation.WorkBudget}, EvaluatorVersion: body.EvaluatorVersion, Intent: intent, IntentDigestForm: form, Access: access, Expected: expectedCopy(body.Expected)}
	for _, source := range body.Catalog.Sources {
		in.Sources = append(in.Sources, advisory.Source{Name: source.Name, Data: slices.Clone(source.Data)})
	}
	return in, nil
}
