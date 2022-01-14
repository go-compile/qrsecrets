package main

import (
	"testing"

	"golang.org/x/crypto/argon2"
)

func BenchmarkLowPreset(b *testing.B) {

	o := presetLow()

	masterKey := []byte("mySecurePassword123@@[]")
	salt := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		argon2.Key(masterKey, salt, o.argonIterations, o.argonMemory, o.argonParallelism, o.argonKeyLen)
	}
}

func BenchmarkMediumPreset(b *testing.B) {

	o := presetMedium()

	masterKey := []byte("mySecurePassword123@@[]")
	salt := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		argon2.Key(masterKey, salt, o.argonIterations, o.argonMemory, o.argonParallelism, o.argonKeyLen)
	}
}

func BenchmarkDefaultPreset(b *testing.B) {

	o := presetDefault()

	masterKey := []byte("mySecurePassword123@@[]")
	salt := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		argon2.Key(masterKey, salt, o.argonIterations, o.argonMemory, o.argonParallelism, o.argonKeyLen)
	}
}

func BenchmarkHighPreset(b *testing.B) {

	o := presetHigh()

	masterKey := []byte("mySecurePassword123@@[]")
	salt := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		argon2.Key(masterKey, salt, o.argonIterations, o.argonMemory, o.argonParallelism, o.argonKeyLen)
	}
}

func BenchmarkVeryHighPreset(b *testing.B) {

	o := presetVeryHigh()

	masterKey := []byte("mySecurePassword123@@[]")
	salt := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		argon2.Key(masterKey, salt, o.argonIterations, o.argonMemory, o.argonParallelism, o.argonKeyLen)
	}
}

func BenchmarkSlowSecurePreset(b *testing.B) {

	o := presetSlowSecure()

	masterKey := []byte("mySecurePassword123@@[]")
	salt := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		argon2.Key(masterKey, salt, o.argonIterations, o.argonMemory, o.argonParallelism, o.argonKeyLen)
	}
}
