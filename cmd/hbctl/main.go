package main

import (
	"os"

	"github.com/rsturla/hbctl/internal/cli"
)

func main() {
	app := cli.New("hbctl", "Hummingbird node management CLI")
	app.Register(
		&versionCmd{},
		&healthCmd{},
		&statsCmd{},
		&logsCmd{},
		&dmesgCmd{},
		&serviceStatusCmd{},
		&configGetCmd{},
		&configApplyCmd{},
		&upgradeCmd{},
		&rollbackCmd{},
		&rebootCmd{},
		&bootstrapCmd{},
		&genTokenCmd{},
	)

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
