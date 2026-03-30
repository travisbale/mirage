package phishlet

import "github.com/travisbale/mirage/internal/aitm"

// Compiler satisfies the phishletCompiler interface defined in the aitm package.
type Compiler struct{}

func (Compiler) Compile(yaml string) (*aitm.Phishlet, error) {
	return Compile(yaml)
}
