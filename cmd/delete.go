package cmd

import (
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/viveksinghggits/akcess/pkg/kube"
	"github.com/viveksinghggits/akcess/pkg/store"
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete the kubernetes resources that were made specific allow command",
	RunE: func(cmd *cobra.Command, args []string) error {
		allFlag, _ := cmd.Flags().GetBool("all")
		if allFlag {
			s, err := store.NewFileStore()
			if err != nil {
				return errors.Wrap(err, "Creating store instance")
			}
			list, err := s.List()
			if err != nil {
				return errors.Wrap(err, "Calling list from store")
			}
			for _, c := range list {
				kube.DeleteResources(c.Id, kubeConfigPathDel)
			}
		} else {
			kube.DeleteResources(delIdentifier, kubeConfigPathDel)
		}
		return nil
	},
}
