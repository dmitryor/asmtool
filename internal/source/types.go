package source

// LabelKind classifies how a label was declared in source.
type LabelKind int

const (
	LabelUnknown LabelKind = iota
	LabelProc              // `Name PROC NEAR`
	LabelGlobal            // `Name:` (single colon, no @@ prefix)
	LabelExport            // `Name::` (double colon -- cross-PROC visible)
	LabelLocal             // `@@Name:` (TASM-scoped local within enclosing PROC)
	LabelData              // a label preceding db/dw/dd/dq
	LabelEqu               // `Name EQU value`
	LabelMacro             // `Name MACRO ... ENDM`
)

func (k LabelKind) String() string {
	switch k {
	case LabelProc:
		return "PROC"
	case LabelGlobal:
		return "global"
	case LabelExport:
		return "export"
	case LabelLocal:
		return "local"
	case LabelData:
		return "data"
	case LabelEqu:
		return "EQU"
	case LabelMacro:
		return "MACRO"
	}
	return "unknown"
}

// Label is a declaration site recorded during source parsing.
type Label struct {
	Name string
	Kind LabelKind
	File string
	Line int
	// EnclosingProc is the name of the PROC this label was declared inside,
	// if any. Empty for labels declared at module scope or for PROC labels
	// themselves. Used for resolving @@-local references.
	EnclosingProc string
}

// RefKind tags how a referenced symbol is being used at the call site.
type RefKind int

const (
	RefUnknown   RefKind = iota
	RefCall              // call X
	RefJmp               // jmp X / j[cond] X
	RefOffset            // offset X (address-as-value)
	RefMem               // [X] / [X+N] / seg:[X] -- memory operand
	RefDataWord          // dw X (one entry of a word data definition)
	RefDataByte          // db X
	RefDataDword         // dd X
	RefImm               // mov reg, X -- immediate that resolves to a label
)

func (k RefKind) String() string {
	switch k {
	case RefCall:
		return "call"
	case RefJmp:
		return "jmp"
	case RefOffset:
		return "offset"
	case RefMem:
		return "mem"
	case RefDataWord:
		return "dw"
	case RefDataByte:
		return "db"
	case RefDataDword:
		return "dd"
	case RefImm:
		return "imm"
	}
	return "?"
}

// Ref is a symbol use-site found during source scanning.
type Ref struct {
	Target        string // symbol name (without leading @@)
	Kind          RefKind
	File          string
	Line          int
	EnclosingProc string // resolves @@-local references
	IsLocal       bool   // true if this reference was @@-prefixed in source
	// Source text of the line (excluding trailing comment) -- helpful for
	// downstream display and for the relocation classifier.
	Text string
}

// Proc is a parsed PROC block.
type Proc struct {
	Name      string
	File      string
	StartLine int // line of "Name PROC ..."
	EndLine   int // line of corresponding ENDP
	// FirstBodyLine is the line after the PROC header (used for read_proc).
	FirstBodyLine int
	// LocalLabels accumulated during parsing (@@-prefixed labels declared
	// inside this PROC).
	LocalLabels []*Label
}

// File is a parsed module file.
type File struct {
	Path     string
	Lines    []string // 1-indexed via Lines[i-1]; raw source (with comments) for read_proc
	Procs    []*Proc
	Labels   []*Label // all top-level declarations (PROC, global, export, data, EQU, MACRO)
	Refs     []*Ref
	Includes []string // include directives found, in declaration order
}
