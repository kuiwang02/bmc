package main

// chassis-control sends a chassis control command to a system, e.g. to power it
// on, or do a hard reset.

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/kuiwang02/bmc"
	"github.com/kuiwang02/bmc/pkg/ipmi"

	"github.com/alecthomas/kingpin"
)

var (
	argBMCAddr = kingpin.Arg("addr", "IP[:port] of the BMC to control.").
			Required().
			String()
	argCommand = kingpin.Arg("command", "The command to send (on/off/cycle/reset/interrupt/softoff).").
			Required().
			String()
	flgUsername = kingpin.Flag("username", "The username to connect as.").
			Required().
			String()
	flgPassword = kingpin.Flag("password", "The password of the user to connect as.").
			Required().
			String()

	cmdControls = map[string]ipmi.ChassisControl{
		"off":       ipmi.ChassisControlPowerOff,
		"on":        ipmi.ChassisControlPowerOn,
		"cycle":     ipmi.ChassisControlPowerCycle,
		"reset":     ipmi.ChassisControlHardReset,
		"interrupt": ipmi.ChassisControlDiagnosticInterrupt,
		"softoff":   ipmi.ChassisControlSoftPowerOff,
	}
)

func lookupCommand(cmd string) (ipmi.ChassisControl, error) {
	if ctrl, ok := cmdControls[cmd]; ok {
		return ctrl, nil
	}
	return ipmi.ChassisControlPowerOff, fmt.Errorf("invalid command: %v", cmd)
}

func main() {
	kingpin.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	machine, err := bmc.Dial(ctx, *argBMCAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer machine.Close()

	log.Printf("connected to %v over IPMI v%v", machine.Address(), machine.Version())

	sess, err := machine.NewSession(ctx, &bmc.SessionOpts{
		Username:          *flgUsername,
		Password:          []byte(*flgPassword),
		MaxPrivilegeLevel: ipmi.PrivilegeLevelOperator,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer sess.Close(ctx)

	cmd, err := lookupCommand(*argCommand)
	if err != nil {
		log.Fatal(err)
	}
	if err := sess.ChassisControl(ctx, cmd); err != nil {
		log.Fatal(err)
	}
}
