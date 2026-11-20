package all

import (
	"encoding/json"
	"flag"
	"os"

	"github.com/xtls/xray-core/features/egress"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdEgress = &base.Command{
	UsageLine:   "{{.Exec}} egress [-interface auto|name] [-exclude name]",
	Short:       "Inspect read-only outbound adapter selection",
	CustomFlags: true,
	Long: `egress performs a read-only preflight using the same route-metric selector
used by the Windows TUN outbound binding. It prints the per-family selection
as JSON and does not require a running core or change network settings.

The -exclude flag can be repeated to omit adapters such as the app-owned TUN.`,
	Run: func(command *base.Command, args []string) {
		interfaceName := "auto"
		var excluded repeatedStringFlag
		command.Flag.StringVar(&interfaceName, "interface", "auto", "")
		command.Flag.Var(&excluded, "exclude", "")
		if err := command.Flag.Parse(args); err != nil {
			base.SetExitStatus(2)
			return
		}
		if command.Flag.NArg() != 0 {
			command.Usage()
			return
		}
		snapshot := egress.Preview(egress.Options{
			InterfaceName:      interfaceName,
			ExcludedInterfaces: excluded,
		})
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(snapshot); err != nil {
			base.Fatalf("failed to encode egress preflight: %v", err)
		}
	},
}

type repeatedStringFlag []string

func (values *repeatedStringFlag) String() string {
	if values == nil {
		return ""
	}
	return "repeated adapter name"
}

func (values *repeatedStringFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

var _ flag.Value = (*repeatedStringFlag)(nil)
