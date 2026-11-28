//go:build windows

package main

import (
	"context"
	"log"
	"os"

	"wedecent.com/wedecent/internal/scmbroker"
	"wedecent.com/wedecent/internal/winservice"
)

const brokerServiceName = "WeDecentSCMBroker"

func main() {
	err := winservice.Run(brokerServiceName, func(ctx context.Context) error {
		return scmbroker.RunContext(ctx)
	})
	if err != nil {
		log.Printf("SCM broker stopped: %v", err)
		os.Exit(1)
	}
}
