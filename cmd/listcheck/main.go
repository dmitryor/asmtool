package main

import (
	"fmt"
	"github.com/orlovsky/jwasm-mcp/internal/jwasm"
)
func main() {
	lf, err := jwasm.ParseListing("/tmp/jwasm-out/retal.lst")
	if err != nil { panic(err) }
	procs := 0
	for _, s := range lf.Symbols {
		if s.Kind == jwasm.SymProc {
			procs++
		}
		if s.Name == "Main" || s.Name == "PlotPixel" || s.Name == "Blit" {
			fmt.Printf("  %s kind=%v val=%x has=%v seg=%s\n", s.Name, s.Kind, s.Value, s.HasAddr, s.Segment)
		}
	}
	fmt.Printf("total=%d procs=%d\n", len(lf.Symbols), procs)
}
