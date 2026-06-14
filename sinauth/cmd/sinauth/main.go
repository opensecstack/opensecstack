package main

import (
	"os"
)

func main() {
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
