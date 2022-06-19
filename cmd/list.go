package cmd

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/viveksinghggits/akcess/pkg/store"
)

// akcess list, to get set of resources created, so that we can delete them later
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List the number of times we ran the allow command",
	Long: `list can be used to figure out how many times the allow command was run.
	Because for every run we are going to create respective CSR, Role and RoleBinding objects,
	this command can then be used to delete the respective CSR, RoleBinding and Role resources for specific request`,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := store.NewFileStore()
		if err != nil {
			return errors.Wrap(err, "Opening file store")
		}

		configs, err := s.List()
		if err != nil {
			return err
		}

		bytes, err := yaml.Marshal(configs)
		if err != nil {
			return errors.Wrap(err, "marshalling list response")
		}

		if err := s.Close(); err != nil {
			return errors.Wrap(err, "closing the filestore after list")
		}

		_, err = fmt.Fprint(os.Stdout, string(bytes))
		return err
	},
}
