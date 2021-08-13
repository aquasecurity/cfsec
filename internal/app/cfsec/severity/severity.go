package severity

type Severity int

const (
	Unknown Severity = iota
	Low
	Medium
	High
	Critical
)
