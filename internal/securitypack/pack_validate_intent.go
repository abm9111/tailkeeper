package securitypack

import (
	"fmt"
	"strings"
)

func validIntentToken(value *packToken, revision string) bool {
	if value == nil {
		return revision == ""
	}
	var prefix string
	switch value.Form {
	case "plain":
		prefix = "sha256:"
	case "keyed":
		prefix = "hmac-sha256:"
	default:
		return false
	}
	return validPrefixedDigest(value.Value, prefix) && revision == strings.TrimPrefix(value.Value, prefix)[:12]
}

func validPolicyToken(value *packToken) bool {
	if value == nil {
		return true
	}
	switch value.Form {
	case "plain":
		return validPlainPolicyToken(value.Value)
	case "keyed":
		return validPrefixedDigest(value.Value, "hmac-sha256:")
	default:
		return false
	}
}

func checkPackIntent(value *packIntent) error {
	if value == nil {
		return nil
	}
	if value.SchemaVersion != 1 || !validIntentToken(value.Digest, value.Revision) {
		return ErrInvalidPack
	}
	for i, network := range value.Network {
		if network.ID != fmt.Sprintf("network-%d", i+1) {
			return ErrInvalidPack
		}
		if _, err := networkFromPack(network); err != nil {
			return err
		}
	}
	for i, ssh := range value.SSH {
		if ssh.ID != fmt.Sprintf("ssh-%d", i+1) {
			return ErrInvalidPack
		}
	}
	return nil
}
