package securitypack

import (
	"slices"

	"github.com/abm9111/tailkeeper/internal/security"
)

func intentToPack(in *security.IntentSet, form tokenForm) (*packIntent, error) {
	if in == nil {
		if form != "" {
			return nil, ErrInvalidPack
		}
		return nil, nil
	}
	out := &packIntent{Revision: in.Revision, SchemaVersion: in.SchemaVersion}
	if in.Digest != "" {
		out.Digest = &packToken{Form: form, Value: in.Digest}
	} else if form != "" {
		return nil, ErrInvalidPack
	}
	for _, value := range in.Network {
		v, err := networkToPack(value)
		if err != nil {
			return nil, err
		}
		out.Network = append(out.Network, v)
	}
	for _, value := range in.SSH {
		out.SSH = append(out.SSH, packSSH{Accept: slices.Clone(value.Accept), Check: slices.Clone(value.Check), Deny: slices.Clone(value.Deny), Dst: slices.Clone(value.Destinations), ID: value.ID, Src: value.Source})
	}
	return out, nil
}

func networkToPack(value security.NetworkExpectation) (packNetwork, error) {
	out := packNetwork{Accept: slices.Clone(value.Accept), Deny: slices.Clone(value.Deny), ID: value.ID, Proto: value.Protocol, Src: value.Source}
	names := make([]string, 0, len(value.SourcePostureAttributes))
	for name := range value.SourcePostureAttributes {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		attribute, err := attributeToPack(name, value.SourcePostureAttributes[name])
		if err != nil {
			return packNetwork{}, err
		}
		out.SrcPostureAttrs = append(out.SrcPostureAttrs, attribute)
	}
	return out, nil
}

func attributeToPack(name string, value security.Scalar) (packAttribute, error) {
	out := packAttribute{Name: name}
	switch value.Kind {
	case security.ScalarString:
		if value.Number != "" || value.Bool {
			return packAttribute{}, ErrInvalidPack
		}
		out.String = ownedString(&value.String)
	case security.ScalarNumber:
		if value.String != "" || value.Bool {
			return packAttribute{}, ErrInvalidPack
		}
		var checked security.Scalar
		if err := checked.UnmarshalJSON([]byte(value.Number)); err != nil || checked.Kind != security.ScalarNumber || checked.Number != value.Number {
			return packAttribute{}, ErrInvalidPack
		}
		out.Number = ownedString(&value.Number)
	case security.ScalarBool:
		if value.String != "" || value.Number != "" {
			return packAttribute{}, ErrInvalidPack
		}
		out.Bool = ownedBool(&value.Bool)
	default:
		return packAttribute{}, ErrInvalidPack
	}
	return out, nil
}

func intentFromPack(in *packIntent) (*security.IntentSet, tokenForm, error) {
	if in == nil {
		return nil, "", nil
	}
	out := &security.IntentSet{SchemaVersion: in.SchemaVersion, Revision: in.Revision}
	var form tokenForm
	if in.Digest != nil {
		out.Digest, form = in.Digest.Value, in.Digest.Form
	}
	for _, value := range in.Network {
		v, err := networkFromPack(value)
		if err != nil {
			return nil, "", err
		}
		out.Network = append(out.Network, v)
	}
	for _, value := range in.SSH {
		out.SSH = append(out.SSH, security.SSHExpectation{Accept: slices.Clone(value.Accept), Check: slices.Clone(value.Check), Deny: slices.Clone(value.Deny), Destinations: slices.Clone(value.Dst), ID: value.ID, Source: value.Src})
	}
	return out, form, nil
}

func networkFromPack(value packNetwork) (security.NetworkExpectation, error) {
	out := security.NetworkExpectation{Accept: slices.Clone(value.Accept), Deny: slices.Clone(value.Deny), ID: value.ID, Protocol: value.Proto, Source: value.Src}
	if len(value.SrcPostureAttrs) > 0 {
		out.SourcePostureAttributes = make(security.PostureAttributes, len(value.SrcPostureAttrs))
	}
	previous := ""
	for i, attr := range value.SrcPostureAttrs {
		if i > 0 && attr.Name <= previous {
			return security.NetworkExpectation{}, ErrInvalidPack
		}
		scalar, err := attributeFromPack(attr)
		if err != nil {
			return security.NetworkExpectation{}, err
		}
		out.SourcePostureAttributes[attr.Name] = scalar
		previous = attr.Name
	}
	return out, nil
}

func attributeFromPack(value packAttribute) (security.Scalar, error) {
	members := 0
	if value.String != nil {
		members++
	}
	if value.Number != nil {
		members++
	}
	if value.Bool != nil {
		members++
	}
	if members != 1 {
		return security.Scalar{}, ErrInvalidPack
	}
	if value.String != nil {
		return security.Scalar{Kind: security.ScalarString, String: *value.String}, nil
	}
	if value.Bool != nil {
		return security.Scalar{Kind: security.ScalarBool, Bool: *value.Bool}, nil
	}
	var scalar security.Scalar
	if err := scalar.UnmarshalJSON([]byte(*value.Number)); err != nil || scalar.Kind != security.ScalarNumber || scalar.Number != *value.Number {
		return security.Scalar{}, ErrInvalidPack
	}
	return scalar, nil
}
