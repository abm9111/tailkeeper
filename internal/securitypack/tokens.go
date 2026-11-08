package securitypack

func validPlainPolicyToken(token string) bool {
	if len(token) != 66 {
		return false
	}
	if token[0] != '"' || token[65] != '"' {
		return false
	}
	for i := 1; i < 65; i++ {
		c := token[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
