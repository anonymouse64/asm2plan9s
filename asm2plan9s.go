/*
 * Minio Cloud Storage, (C) 2016-2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type Compiler int

var assembler = flag.String("as", "gas", "assembler to use")
var assemblerString string
var fileOpt = flag.String("file", "", "file to assemble")

const (
	GAS Compiler = iota
	ARMCC
	YASM
)

type Instruction struct {
	instruction string
	lineno      int
	commentPos  int
	inDefine    bool
	assembled   string
	opcodes     []byte
}

type Assembler struct {
	Prescan      bool
	Instructions []Instruction
	Compact      bool
}

// assemble assembles an array of lines into their
// resulting plan9 equivalents
func (a *Assembler) assemble(lines []string) ([]string, error) {

	result := make([]string, 0)

	for lineno, line := range lines {
		startsWithTab := strings.HasPrefix(line, "\t")
		line := strings.Replace(line, "\t", "    ", -1)
		fields := strings.Split(line, "//")
		if len(fields) == 2 && (startsAfterLongWordByteSequence(fields[0]) || len(fields[0]) == 65) {

			// test whether string before instruction is terminated with a backslash (so used in a #define)
			trimmed := strings.TrimSpace(fields[0])
			inDefine := len(trimmed) > 0 && string(trimmed[len(trimmed)-1]) == `\`

			// While prescanning collect the instructions
			if a.Prescan {
				ins := Instruction{instruction: fields[1], lineno: lineno, commentPos: len(fields[0]), inDefine: inDefine}
				a.Instructions = append(a.Instructions, ins)
				continue
			}

			var ins *Instruction
			for i := range a.Instructions {
				if lineno == a.Instructions[i].lineno {
					ins = &a.Instructions[i]
				}
			}
			if ins == nil {
				if a.Compact {
					continue
				}
				panic("failed to find entry with correct line number")
			}
			if startsWithTab {
				ins.assembled = strings.Replace(ins.assembled, "    ", "\t", 1)
			}
			result = append(result, ins.assembled)
		} else if !a.Prescan {
			if startsWithTab {
				line = strings.Replace(line, "    ", "\t", 1)
			}
			result = append(result, line)
		}
	}

	return result, nil
}

/*
 * Minio Cloud Storage, (C) 2016-2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

func genericAssembler(instructions []Instruction) error {
	// switch on what assembler this is
	switch {
	case strings.Contains(assemblerString, "yasm"):
		return yasm(instructions)
	case strings.Contains(assemblerString, "gcc"):
		return gas(instructions)
	case strings.Contains(assemblerString, "armcc"):
		return fmt.Errorf("TODO : armcc not supported yet")
	}
}

// as: assemble instruction by either invoking yasm or gas
func as(instructions []Instruction) error {

	// First to yasm (will return error when not installed)
	e := yasm(instructions)
	if e == nil {
		return e
	}
	// Try gas if yasm not installed
	return gas(instructions)
}

// See below for YASM support (older, no AVX512)

///////////////////////////////////////////////////////////////////////////////
//
// G A S   S U P P O R T
//
///////////////////////////////////////////////////////////////////////////////

//
// frank@hemelmeer: asm2plan9s$ more example.s
// .intel_syntax noprefix
//
//     VPANDQ   ZMM0, ZMM1, ZMM2
//
// frank@hemelmeer: asm2plan9s$ as -o example.o -al=example.lis example.s
// frank@hemelmeer: asm2plan9s$ more example.lis
// GAS LISTING example.s                   page 1
// 1                    .intel_syntax noprefix
// 2
// 3 0000 62F1F548          VPANDQ   ZMM0, ZMM1, ZMM2
// 3      DBC2
//

func gas(instructions []Instruction) error {

	tmpfile, err := ioutil.TempFile("", "asm2plan9s")
	if err != nil {
		return err
	}
	if _, err := tmpfile.Write([]byte(fmt.Sprintf(".intel_syntax noprefix\n"))); err != nil {
		return err
	}

	for _, instr := range instructions {
		instrFields := strings.Split(instr.instruction, "/*")
		if len(instrFields) == 1 {
			instrFields = strings.Split(instr.instruction, ";") // try again with ; separator
		}
		content := []byte(instrFields[0] + "\n")

		if _, err := tmpfile.Write([]byte(content)); err != nil {
			return err
		}
	}

	if err := tmpfile.Close(); err != nil {
		return err
	}

	asmFile := tmpfile.Name() + ".asm"
	lisFile := tmpfile.Name() + ".lis"
	objFile := tmpfile.Name() + ".obj"
	os.Rename(tmpfile.Name(), asmFile)

	defer os.Remove(asmFile) // clean up
	defer os.Remove(lisFile) // clean up
	defer os.Remove(objFile) // clean up

	// as -o example.o -al=example.lis example.s
	app := "as"

	arg0 := "-o"
	arg1 := objFile
	arg2 := fmt.Sprintf("-aln=%s", lisFile)
	arg3 := asmFile

	cmd := exec.Command(app, arg0, arg1, arg2, arg3)
	cmb, err := cmd.CombinedOutput()
	if err != nil {
		asmErrs := strings.Split(string(cmb)[len(asmFile)+1:], ":")
		asmErr := strings.Join(asmErrs[1:], ":")
		// TODO: Fix proper error reporting
		lineno := -1
		instr := "TODO: fix"
		return errors.New(fmt.Sprintf("GAS error (line %d for '%s'):", lineno+1, strings.TrimSpace(instr)) + asmErr)
	}

	opcodes, err := toPlan9sGas(lisFile)
	if err != nil {
		return err
	}

	fmt.Printf("opcodes : %+v\n", opcodes)
	fmt.Printf("instructions : %+v\n", instructions)

	if len(instructions) != len(opcodes) {
		panic("Unequal length between instructions to be assembled and opcodes returned")
	}

	for i, opcode := range opcodes {
		assembled, err := toPlan9s(opcode, instructions[i].instruction, instructions[i].commentPos, instructions[i].inDefine)
		if err != nil {
			return err
		}
		instructions[i].assembled = assembled
		instructions[i].opcodes = make([]byte, len(opcode))
		copy(instructions[i].opcodes, opcode)
	}

	return nil
}

func toPlan9sGas(listFile string) ([][]byte, error) {

	opcodes := make([][]byte, 0, 10)

	outputLines, err := readLines(listFile, nil)
	if err != nil {
		return opcodes, err
	}

	var regexpHeader = regexp.MustCompile(`^\s+(\d+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)`)
	var regexpSequel = regexp.MustCompile(`^\s+(\d+)\s+([0-9a-fA-F]+)`)

	lineno, opcode := -1, make([]byte, 0, 10)

	for _, line := range outputLines {

		if match := regexpHeader.FindStringSubmatch(line); len(match) > 2 {
			l, e := strconv.Atoi(match[1])
			if e != nil {
				panic(e)
			}
			if lineno != -1 {
				opcodes = append(opcodes, opcode)
			}
			lineno = l
			opcode = make([]byte, 0, 10)
			b, e := hex.DecodeString(match[2])
			if e != nil {
				panic(e)
			}
			opcode = append(opcode, b...)
		} else if match := regexpSequel.FindStringSubmatch(line); len(match) > 2 {
			l, e := strconv.Atoi(match[1])
			if e != nil {
				panic(e)
			}
			if l != lineno {
				panic("bad line number)")
			}
			b, e := hex.DecodeString(match[2])
			if e != nil {
				panic(e)
			}
			opcode = append(opcode, b...)
		}
	}

	opcodes = append(opcodes, opcode)

	return opcodes, nil
}

///////////////////////////////////////////////////////////////////////////////
//
// Y A S M   S U P P O R T
//
///////////////////////////////////////////////////////////////////////////////

//
// yasm-assemble-disassemble-roundtrip-sse.txt
//
// franks-mbp:sse frankw$ more assembly.asm
// [bits 64]
//
// VPXOR   YMM4, YMM2, YMM3    ; X4: Result
// franks-mbp:sse frankw$ yasm assembly.asm
// franks-mbp:sse frankw$ hexdump -C assembly
// 00000000  c5 ed ef e3                                       |....|
// 00000004
// franks-mbp:sse frankw$ echo 'lbl: db 0xc5, 0xed, 0xef, 0xe3' | yasm -f elf - -o assembly.o
// franks-mbp:sse frankw$ gobjdump -d -M intel assembly.o
//
// assembly.o:     file format elf32-i386
//
//
// Disassembly of section .text:
//
// 00000000 <.text>:
// 0:   c5 ed ef e3             vpxor  ymm4,ymm2,ymm3

func yasm(instructions []Instruction) error {
	for i, ins := range instructions {
		assembled, opcodes, err := yasmSingle(ins.instruction, ins.lineno, ins.commentPos, ins.inDefine)
		if err != nil {
			return err
		}
		instructions[i].assembled = assembled
		instructions[i].opcodes = make([]byte, len(opcodes))
		copy(instructions[i].opcodes[:], opcodes)
	}
	return nil
}

func yasmSingle(instr string, lineno, commentPos int, inDefine bool) (string, []byte, error) {

	instrFields := strings.Split(instr, "/*")
	content := []byte("[bits 64]\n" + instrFields[0])
	tmpfile, err := ioutil.TempFile("", "asm2plan9s")
	if err != nil {
		return "", nil, err
	}

	if _, err := tmpfile.Write(content); err != nil {
		return "", nil, err
	}
	if err := tmpfile.Close(); err != nil {
		return "", nil, err
	}

	asmFile := tmpfile.Name() + ".asm"
	objFile := tmpfile.Name() + ".obj"
	os.Rename(tmpfile.Name(), asmFile)

	defer os.Remove(asmFile) // clean up
	defer os.Remove(objFile) // clean up

	app := "yasm"

	arg0 := "-o"
	arg1 := objFile
	arg2 := asmFile

	cmd := exec.Command(app, arg0, arg1, arg2)
	cmb, err := cmd.CombinedOutput()
	if err != nil {
		if len(string(cmb)) == 0 { // command invocation failed
			return "", nil, errors.New("exec error: YASM not installed?")
		}
		yasmErrs := strings.Split(string(cmb)[len(asmFile)+1:], ":")
		yasmErr := strings.Join(yasmErrs[1:], ":")
		return "", nil, errors.New(fmt.Sprintf("YASM error (line %d for '%s'):", lineno+1, strings.TrimSpace(instr)) + yasmErr)
	}

	return toPlan9sYasm(objFile, instr, commentPos, inDefine)
}

func toPlan9sYasm(objFile, instr string, commentPos int, inDefine bool) (string, []byte, error) {
	opcodes, err := ioutil.ReadFile(objFile)
	if err != nil {
		return "", nil, err
	}

	s, err := toPlan9s(opcodes, instr, commentPos, inDefine)
	return s, opcodes, err
}

func toPlan9s(opcodes []byte, instr string, commentPos int, inDefine bool) (string, error) {
	sline := "    "
	i := 0
	// First do QUADs (as many as needed)
	for ; len(opcodes) >= 8; i++ {
		if i != 0 {
			sline += "; "
		}
		sline += fmt.Sprintf("QUAD $0x%02x%02x%02x%02x%02x%02x%02x%02x", opcodes[7], opcodes[6], opcodes[5], opcodes[4], opcodes[3], opcodes[2], opcodes[1], opcodes[0])

		opcodes = opcodes[8:]
	}
	// Then do LONGs (as many as needed)
	for ; len(opcodes) >= 4; i++ {
		if i != 0 {
			sline += "; "
		}
		sline += fmt.Sprintf("LONG $0x%02x%02x%02x%02x", opcodes[3], opcodes[2], opcodes[1], opcodes[0])

		opcodes = opcodes[4:]
	}

	// Then do a WORD (if needed)
	if len(opcodes) >= 2 {

		if i != 0 {
			sline += "; "
		}
		sline += fmt.Sprintf("WORD $0x%02x%02x", opcodes[1], opcodes[0])

		i++
		opcodes = opcodes[2:]
	}

	// And close with a BYTE (if needed)
	if len(opcodes) == 1 {
		if i != 0 {
			sline += "; "
		}
		sline += fmt.Sprintf("BYTE $0x%02x", opcodes[0])

		i++
		opcodes = opcodes[1:]
	}

	if inDefine {
		if commentPos > commentPos-2-len(sline) {
			if commentPos-2-len(sline) > 0 {
				sline += strings.Repeat(" ", commentPos-2-len(sline))
			}
		} else {
			sline += " "
		}
		sline += `\ `
	} else {
		if commentPos > len(sline) {
			if commentPos-len(sline) > 0 {
				sline += strings.Repeat(" ", commentPos-len(sline))
			}
		} else {
			sline += " "
		}
	}

	if instr != "" {
		sline += "//" + instr
	}

	return strings.TrimRightFunc(sline, unicode.IsSpace), nil
}

// startsAfterLongWordByteSequence determines if an assembly instruction
// starts on a position after a combination of LONG, WORD, BYTE sequences
func startsAfterLongWordByteSequence(prefix string) bool {

	if len(strings.TrimSpace(prefix)) != 0 && !strings.HasPrefix(prefix, "    LONG $0x") &&
		!strings.HasPrefix(prefix, "    WORD $0x") && !strings.HasPrefix(prefix, "    BYTE $0x") {
		return false
	}

	length := 4 + len(prefix) + 1

	for objcodes := 3; objcodes <= 8; objcodes++ {

		ls, ws, bs := 0, 0, 0

		oc := objcodes

		for ; oc >= 4; oc -= 4 {
			ls++
		}
		if oc >= 2 {
			ws++
			oc -= 2
		}
		if oc == 1 {
			bs++
		}
		size := 4 + ls*(len("LONG $0x")+8) + ws*(len("WORD $0x")+4) + bs*(len("BYTE $0x")+2) + (ls+ws+bs-1)*len("; ")

		if length == size+6 { // comment starts after a space
			return true
		}
	}
	return false
}

// combineLines shortens the output by combining consecutive lines into a larger list of opcodes
func (a *Assembler) combineLines() {
	startIndex, startLine, opcodes := -1, -1, make([]byte, 0, 1024)
	combined := make([]Instruction, 0, 100)
	for i, ins := range a.Instructions {
		if startIndex == -1 {
			startIndex, startLine = i, ins.lineno
		}
		if ins.lineno != startLine+(i-startIndex) { // we have found a non-consecutive line
			combiAssem, _ := toPlan9s(opcodes, "", 0, false)
			combiIns := Instruction{assembled: combiAssem, lineno: startLine, inDefine: false}

			combined = append(combined, combiIns)
			opcodes = opcodes[:0]
			startIndex, startLine = i, ins.lineno
		}
		opcodes = append(opcodes, ins.opcodes...)
	}
	if len(opcodes) > 0 {
		combiAssem, _ := toPlan9s(opcodes, "", 0, false)
		ins := Instruction{assembled: combiAssem, lineno: startLine, inDefine: false}

		combined = append(combined, ins)
	}

	a.Instructions = combined
}

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string, in io.Reader) ([]string, error) {
	if in == nil {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		in = file
	}

	var lines []string
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// writeLines writes the lines to the given file.
func writeLines(lines []string, path string, out io.Writer) error {
	if path != "" {
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()
		out = file
	}

	w := bufio.NewWriter(out)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func assemble(lines []string, compact bool) (result []string, err error) {

	// TODO: Make compaction configurable
	a := Assembler{Prescan: true, Compact: compact}

	_, err = a.assemble(lines)
	if err != nil {
		return result, err
	}

	assemblerString = strings.ToLower(*assembler)
	if assemblerString == "gas" {
		err = gas(a.Instructions)
	} else if assemblerString == "yasm" {
		err = yasm(a.Instructions)
	} else if _, err = os.Stat(assemblerString); err == nil {
		err = genericAssembler(a.Instructions)
	} else if assemblerString == "armcc" {
		//TODO implement armcc
	} else {
		return nil, fmt.Errorf("assembler %s not supported\n", *assembler)
	}

	if err != nil {
		return result, err
	}

	if a.Compact {
		a.combineLines()
	}

	a.Prescan = false
	result, err = a.assemble(lines)
	if err != nil {
		return result, err
	}

	return result, nil
}

func main() {

	flag.Parse()

	var file = *fileOpt

	var lines []string
	var err error
	if len(file) > 0 {
		fmt.Println("Processing file", file)
		lines, err = readLines(file, nil)
	} else {
		lines, err = readLines("", os.Stdin)
	}
	if err != nil {
		log.Fatalf("readLines: %s", err)
	}

	result, err := assemble(lines, false)
	if err != nil {
		fmt.Print(err)
		os.Exit(-1)
	}

	err = writeLines(result, file, os.Stdout)
	if err != nil {
		log.Fatalf("writeLines: %s", err)
	}
}
