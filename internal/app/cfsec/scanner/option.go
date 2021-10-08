package scanner

// Option ...
type Option func(s *Scanner)

// OptionIncludePassed ...
func OptionIncludePassed() func(s *Scanner) {
	return func(s *Scanner) {
		s.includePassed = true
	}
}

// OptionIncludeIgnored ...
func OptionIncludeIgnored() func(s *Scanner) {
	return func(s *Scanner) {
		s.includeIgnored = true
	}
}

// OptionExcludeRules ...
func OptionExcludeRules(ruleIDs []string) func(s *Scanner) {
	return func(s *Scanner) {
		s.excludedRuleIDs = ruleIDs
	}
}

// OptionIgnoreCheckErrors ...
func OptionIgnoreCheckErrors(ignore bool) func(s *Scanner) {
	return func(s *Scanner) {
		s.ignoreCheckErrors = ignore
	}
}

// OptionWithWorkspaceName ...
func OptionWithWorkspaceName(workspaceName string) func(s *Scanner) {
	return func(s *Scanner) {
		s.workspaceName = workspaceName
	}
}
