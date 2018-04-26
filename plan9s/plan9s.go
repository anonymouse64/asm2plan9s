package plan9s

import (
	"fmt"
	"strings"
	"unicode"
)

func ToPlan9s(opcodes []byte, instr string, commentPos int, inDefine bool) (string, error) {
	sline := "    "
	i := 0
	// First do QUADs (as many as needed)
	for ; len(opcodes) >= 8; i++ {
		if i != 0 {
			sline += "; "
		}
		sline += fmt.Sprintf("QUAD $0x%02x%02x%02x%02x%02x%02x%02x%02x", opcodes[0], opcodes[1], opcodes[2], opcodes[3], opcodes[4], opcodes[5], opcodes[6], opcodes[7])

		opcodes = opcodes[8:]
	}
	// Then do LONGs (as many as needed)
	for ; len(opcodes) >= 4; i++ {
		if i != 0 {
			sline += "; "
		}
		sline += fmt.Sprintf("LONG $0x%02x%02x%02x%02x", opcodes[0], opcodes[1], opcodes[2], opcodes[3])

		opcodes = opcodes[4:]
	}

	// Then do a WORD (if needed)
	if len(opcodes) >= 2 {

		if i != 0 {
			sline += "; "
		}
		sline += fmt.Sprintf("WORD $0x%02x%02x", opcodes[0], opcodes[1])

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
