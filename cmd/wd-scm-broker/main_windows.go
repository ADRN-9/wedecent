//go:build windows

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"wedecent.com/wedecent/internal/scmbroker"
	"wedecent.com/wedecent/internal/winservice"
)

const brokerServiceName = "WeDecentSCMBroker"

func main() {
	if len(os.Args) == 2 {
		var err error
		switch os.Args[1] {
		case "--install":
			executable, pathErr := os.Executable()
			if pathErr != nil {
				err = pathErr
			} else {
				err = scmbroker.InstallService(executable)
			}
		case "--uninstall":
			err = scmbroker.UninstallService()
		default:
			err = fmt.Errorf("unsupported wd-scm-broker command %q", os.Args[1])
		}
		if err != nil {
			log.Printf("SCM broker management failed: %v", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		log.Printf("SCM broker accepts only --install or --uninstall")
		os.Exit(2)
	}
	err := winservice.Run(brokerServiceName, func(ctx context.Context) error {
		return scmbroker.RunContext(ctx)
	})
	if err != nil {
		log.Printf("SCM broker stopped: %v", err)
		os.Exit(1)
	}
}
