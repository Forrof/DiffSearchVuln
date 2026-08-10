// Command go-symbols recovers Go function names from a Mach-O pclntab without
// loading or executing the target binary.
package main

import (
	"debug/gosym"
	"debug/macho"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
)

type symbol struct {
	entry   uint64
	Address string `json:"address"`
	End     string `json:"end"`
	Name    string `json:"name"`
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: go-symbols /path/to/thin-mach-o")
		os.Exit(2)
	}
	if err := run(flag.Arg(0)); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string) error {
	file, err := macho.Open(path)
	if err != nil {
		return fmt.Errorf("open Mach-O: %w", err)
	}
	defer file.Close()

	text := file.Section("__text")
	pcln := file.Section("__gopclntab")
	if text == nil || pcln == nil {
		return errors.New("Mach-O has no __text or __gopclntab section")
	}
	pclnData, err := pcln.Data()
	if err != nil {
		return fmt.Errorf("read __gopclntab: %w", err)
	}
	lineTable := gosym.NewLineTable(pclnData, text.Addr)
	table, err := gosym.NewTable(nil, lineTable)
	if err != nil {
		return fmt.Errorf("parse Go pclntab: %w", err)
	}

	symbols := make([]symbol, 0, len(table.Funcs))
	for _, function := range table.Funcs {
		if function.Name == "" || function.Entry == 0 || function.End <= function.Entry {
			continue
		}
		symbols = append(symbols, symbol{
			entry:   function.Entry,
			Address: fmt.Sprintf("%x", function.Entry),
			End:     fmt.Sprintf("%x", function.End),
			Name:    function.Name,
		})
	}
	sort.Slice(symbols, func(i, j int) bool {
		if symbols[i].entry == symbols[j].entry {
			return symbols[i].Name < symbols[j].Name
		}
		return symbols[i].entry < symbols[j].entry
	})

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	for _, item := range symbols {
		if err := encoder.Encode(item); err != nil {
			return fmt.Errorf("write symbol: %w", err)
		}
	}
	return nil
}
