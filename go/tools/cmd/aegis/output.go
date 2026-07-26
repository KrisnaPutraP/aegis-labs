package main

import (
	"fmt"
	"os"
)

// Colour is a demo aid, so it is switched off the moment output is not going to
// a terminal. A recorded log full of escape codes helps nobody.
var colour = isTerminal(os.Stdout)

const (
	ansiReset = "\033[0m"
	ansiCyan  = "\033[36m"
	ansiGreen = "\033[32m"
	ansiRed   = "\033[31m"
	ansiDim   = "\033[2m"
)

func paint(code, s string) string {
	if !colour {
		return s
	}
	return code + s + ansiReset
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// step prints a heading for a phase of the command.
func step(format string, a ...any) {
	fmt.Printf("\n%s %s\n", paint(ansiCyan, "==>"), fmt.Sprintf(format, a...))
}

// field prints one aligned label and value under a step.
func field(label, format string, a ...any) {
	fmt.Printf("  %-14s %s\n", label, fmt.Sprintf(format, a...))
}

// note prints an indented line of prose, for the point a step is making.
func note(format string, a ...any) {
	fmt.Printf("  %s\n", paint(ansiDim, fmt.Sprintf(format, a...)))
}

// progress prints a line while something slow is running, so a demo that is
// waiting still looks like it is working.
func progress(format string, a ...any) {
	fmt.Printf("  %s\n", paint(ansiDim, fmt.Sprintf(format, a...)))
}

func warn(format string, a ...any) {
	fmt.Printf("  %s %s\n", paint(ansiRed, "warning:"), fmt.Sprintf(format, a...))
}

// headline prints the sentence the demo is meant to land on.
func headline(format string, a ...any) {
	fmt.Printf("\n%s\n", paint(ansiGreen, fmt.Sprintf(format, a...)))
}

// verdict prints an outcome that is not a success, without dressing it up.
func verdict(format string, a ...any) {
	fmt.Printf("\n%s\n", fmt.Sprintf(format, a...))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "\n%s %s\n", paint(ansiRed, "error:"), err)
	os.Exit(1)
}

// shorten renders a hash or an address the way the explorer does, keeping both
// ends so it can still be matched against a block explorer by eye.
func shorten(hex string) string {
	if len(hex) <= 20 {
		return hex
	}
	return hex[:10] + "..." + hex[len(hex)-8:]
}
