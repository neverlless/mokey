package sync

import (
	"os"

	"github.com/neverlless/mokey/v2/cmd"
	"github.com/neverlless/mokey/v2/server"
	"github.com/spf13/cobra"
)

var syncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Run the directory sync once",
	Long:  "Run the directory sync once and exit: 0 ok, 1 errors or another run in progress, 2 held by the safety brake.",
	RunE: func(command *cobra.Command, args []string) error {
		dry, err := command.Flags().GetBool("dry-run")
		if err != nil {
			return err
		}
		command.SilenceUsage = true
		code, err := server.RunSync(command.Context(), dry, command.OutOrStdout())
		if err != nil {
			command.PrintErrln("Error:", err)
		}
		os.Exit(code)
		return nil
	},
}

func init() {
	syncCmd.Flags().Bool("dry-run", false, "plan only, change nothing")
	cmd.Root.AddCommand(syncCmd)
}
