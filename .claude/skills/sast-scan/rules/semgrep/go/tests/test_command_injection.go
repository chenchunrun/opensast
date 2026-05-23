package main

import (
	"context"
	"os/exec"
)

func vulnerable(userInput string) {
	// Positive: exec.Command with variable argument via sh -c
	// ruleid: go.security.command-injection-exec
	exec.Command("sh", "-c", userInput)

	// ruleid: go.security.command-injection-exec
	exec.Command("/bin/sh", "-c", userInput)

	// ruleid: go.security.command-injection-exec
	exec.Command("bash", "-c", userInput)

	// Positive: exec.CommandContext with variable
	// ruleid: go.security.command-injection-exec
	exec.CommandContext(context.Background(), "sh", "-c", userInput)

	// Positive: variable as command name
	// ruleid: go.security.command-injection-exec
	exec.Command(userInput, "-la")
}

func safe() {
	// Negative: literal command and arguments
	// ok: go.security.command-injection-exec
	exec.Command("ls", "-la")

	// ok: go.security.command-injection-exec
	exec.Command("ping", "-c", "3", "example.com")

	// ok: go.security.command-injection-exec
	exec.CommandContext(context.Background(), "echo", "hello")
}
