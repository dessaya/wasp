package cc

import "github.com/iotaledger/wasp/v2/packages/gpa"

type CommonCoin interface {
	gpa.GPA
	Input()
	Output() *bool
}
