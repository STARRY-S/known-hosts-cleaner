package main

import (
	"os"

	"github.com/STARRY-S/known-hosts-cleaner/pkg/commands"
	"github.com/sirupsen/logrus"
)

func main() {
	err := commands.Execute(os.Args[1:])
	if err != nil {
		logrus.Fatal(err)
	}
}
