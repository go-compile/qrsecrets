package main

import (
	"strings"

	"github.com/go-compile/qrsecrets"
	"github.com/pkg/errors"
)

var (
	// ErrUnknownPreset is returned if the preset name doesn't exist
	ErrUnknownPreset = errors.New("unknown security preset")
)

func presetLow() *options {
	o := defaultOptions()

	o.curve = qrsecrets.IDToCurve(qrsecrets.CurveP256)
	o.argonParallelism = 1

	return o
}

func presetMedium() *options {
	o := defaultOptions()

	o.curve = qrsecrets.IDToCurve(qrsecrets.CurveP384)
	o.argonParallelism = 2

	return o
}

func presetDefault() *options {
	o := defaultOptions()

	return o
}

func presetHigh() *options {
	o := defaultOptions()

	o.argonMemory = 64 * 1024
	o.argonIterations = 6

	return o
}

func presetVeryHigh() *options {
	o := defaultOptions()

	o.argonMemory = 64 * 1024
	o.argonIterations = 12

	return o
}

func preset(name string) (*options, error) {
	switch strings.ToLower(name) {
	case "low":
		return presetLow(), nil
	case "medium":
		return presetMedium(), nil
	case "default":
		return presetDefault(), nil
	case "high":
		return presetHigh(), nil
	case "very-high", "very_high":
		return presetVeryHigh(), nil
	default:
		return nil, ErrUnknownPreset
	}
}
