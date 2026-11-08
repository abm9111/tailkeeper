package securitypack

func checkTexts(values ...string) error {
	for _, value := range values {
		if err := checkPackText(value); err != nil {
			return err
		}
	}
	return nil
}

func checkOptionalText(value *string) error {
	if value == nil {
		return nil
	}
	return checkPackText(*value)
}

func checkEvidenceText(value packEvidence) error {
	return checkTexts(value.Asset, value.Context, value.Error, value.Freshness, value.Origin, value.Scope)
}

func checkSnapshotText(value packSnapshot) error {
	if err := checkTexts(value.Context, value.KeyEpoch, value.Scope); err != nil {
		return err
	}
	for _, v := range value.Versions {
		if err := checkTexts(v.Channel, v.Name, v.Role); err != nil {
			return err
		}
		if err := checkOptionalText(v.Value); err != nil {
			return err
		}
		if err := checkEvidenceText(v.Evidence); err != nil {
			return err
		}
	}
	for _, v := range value.Platforms {
		if err := checkTexts(v.OS, v.Variant); err != nil {
			return err
		}
		if err := checkEvidenceText(v.Evidence); err != nil {
			return err
		}
	}
	return checkSnapshotOtherText(value)
}

func checkSnapshotOtherText(value packSnapshot) error {
	for _, v := range value.Features {
		if err := checkPackText(v.Name); err != nil {
			return err
		}
		if err := checkEvidenceText(v.Evidence); err != nil {
			return err
		}
	}
	for _, v := range value.Policies {
		if err := checkPackText(v.Name); err != nil {
			return err
		}
		if err := checkOptionalText(v.Value); err != nil {
			return err
		}
		if err := checkEvidenceText(v.Evidence); err != nil {
			return err
		}
	}
	return nil
}

func checkTokenText(value *packToken) error {
	if value == nil {
		return nil
	}
	return checkTexts(string(value.Form), value.Value)
}

func checkIntentText(value *packIntent) error {
	if value == nil {
		return nil
	}
	if err := checkPackText(value.Revision); err != nil {
		return err
	}
	if err := checkTokenText(value.Digest); err != nil {
		return err
	}
	for _, v := range value.Network {
		if err := checkTexts(v.ID, v.Proto, v.Src); err != nil {
			return err
		}
		if err := checkTexts(v.Accept...); err != nil {
			return err
		}
		if err := checkTexts(v.Deny...); err != nil {
			return err
		}
		for _, a := range v.SrcPostureAttrs {
			if err := checkPackText(a.Name); err != nil {
				return err
			}
			if err := checkOptionalText(a.Number); err != nil {
				return err
			}
			if err := checkOptionalText(a.String); err != nil {
				return err
			}
		}
	}
	return checkSSHText(value.SSH)
}

func checkSSHText(values []packSSH) error {
	for _, v := range values {
		if err := checkTexts(v.ID, v.Src); err != nil {
			return err
		}
		for _, list := range [][]string{v.Accept, v.Check, v.Deny, v.Dst} {
			if err := checkTexts(list...); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkRuleText(value packRule) error {
	return checkTexts(value.Destination, value.Ports, value.Section, value.Source, value.Traffic)
}

func checkAccessText(value *packAccess) error {
	if value == nil {
		return nil
	}
	if err := checkPackText(value.Context); err != nil {
		return err
	}
	if err := checkTexts(value.Selected...); err != nil {
		return err
	}
	if err := checkTokenText(value.PolicyVersion); err != nil {
		return err
	}
	for _, c := range value.Candidates {
		if err := checkPackText(c.Expectation); err != nil {
			return err
		}
		for _, r := range c.Rules {
			if err := checkRuleText(r); err != nil {
				return err
			}
		}
	}
	for _, l := range value.Limits {
		if err := checkPackText(l.Expectation); err != nil {
			return err
		}
		if err := checkTexts(l.Limits...); err != nil {
			return err
		}
	}
	return checkAccessOtherText(value)
}

func checkAccessOtherText(value *packAccess) error {
	for _, o := range value.Owners {
		if err := checkPackText(o.Source); err != nil {
			return err
		}
		if err := checkTexts(o.Tags...); err != nil {
			return err
		}
	}
	for _, w := range value.Witnesses {
		if err := checkTexts(w.Expectation, w.Observed, w.Reason, w.Cell.Destination, w.Cell.Expect, w.Cell.User); err != nil {
			return err
		}
	}
	return nil
}

func checkPackTextLeaves(value packEnvelope) error {
	if err := checkTexts(value.Integrity, value.Body.Format, value.Body.Catalog.Digest,
		value.Body.Expected.Report.SHA256, value.Body.Expected.Report.Status); err != nil {
		return err
	}
	if err := checkOptionalText(value.Seal); err != nil {
		return err
	}
	if value.Body.Expected.Access != nil {
		if err := checkTexts(value.Body.Expected.Access.SHA256, value.Body.Expected.Access.Status); err != nil {
			return err
		}
	}
	for _, source := range value.Body.Catalog.Sources {
		if err := checkTexts(source.Name, source.SHA256); err != nil {
			return err
		}
	}
	for _, c := range value.Body.Collected {
		if err := checkTexts(c.Context, c.Explanation, c.Source, c.Status, c.Target.Asset, c.Target.Dimension, c.Target.Scope); err != nil {
			return err
		}
	}
	if err := checkSnapshotText(value.Body.Snapshot); err != nil {
		return err
	}
	if err := checkIntentText(value.Body.Intent); err != nil {
		return err
	}
	return checkAccessText(value.Body.Access)
}
