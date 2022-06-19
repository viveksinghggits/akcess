package cmd

import (
	"github.com/spf13/cobra"

	"github.com/viveksinghggits/akcess/pkg/kube"
)

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete the kubernetes resources that were made specific allow command",
	RunE: func(cmd *cobra.Command, args []string) error {
		return kube.DeleteResources(delIdentifier, kubeConfigPathDel)
	},
}
