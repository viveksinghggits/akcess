package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/viveksinghggits/akcess/pkg/allow"
	"github.com/viveksinghggits/akcess/pkg/utils"
)

var rootCmd = &cobra.Command{
	Use:   utils.Name,
	Short: "Create kubeconfig file with specified fine-grained authorization",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var (
	options           = &allow.AllowOptions{}
	res               = []string{}
	delIdentifier     string
	kubeConfigPathDel string
	delAll            bool
	// VERSION will be overridden by ldflags when we build the project using goreleaser
	VERSION = "DEV"
)

func init() {
	rootCmd.AddCommand(versionCmd, allowCmd, listCmd, deleteCmd)

	allowCmd.Flags().StringSliceVarP(&res, "resource", "r", []string{}, "Resources/subresource to allow access on")
	allowCmd.Flags().StringSliceVarP(&options.Verbs, "verb", "v", []string{}, "Allowed verbs")
	allowCmd.Flags().StringVarP(&options.KubeConfigPath, "kubeconfig", "k", "", "Path to kubeconfig file")
	allowCmd.Flags().StringVarP(&options.Namespace, "namespace", "n", "default", "Namespace of the resource")
	allowCmd.Flags().StringSliceVarP(&options.ResourceNames, "resource-name", "", []string{}, "Resource names to allow access on, they are not validated to be present on the cluster")
	allowCmd.Flags().Int32VarP(&options.ValidFor, "for", "f", 86400, "Duration the access will be allowed for (in minutes), for example --for 10. Defaults to 1 day")
	allowCmd.Flags().StringArrayVarP(&options.Labels, "labels", "l", []string{}, "Labels of the resources the specified access should be allowed on. For example, if you want to allow access to see logs of a set of pods that have same labels, instead of specifying all those pods separately using --resource-name field we can just specify label that is common among those resources")
	allowCmd.Flags().StringVarP(&options.Username, "username", "u", "", "Username to be used in KubeConfig file")
	// required flags for allow command
	allowCmd.MarkFlagRequired("resource")
	allowCmd.MarkFlagRequired("verb")

	deleteCmd.Flags().StringVarP(&delIdentifier, "id", "i", "", "Id for which the k8s resources should be deleted. Can be figured out from list command")
	deleteCmd.Flags().StringVarP(&kubeConfigPathDel, "kubeconfig", "k", "", "Path to kubeconfig file")
	deleteCmd.Flags().BoolVarP(&delAll, "all", "a", false, "flag to delete all resource")
	// required flags for delete command
	// `akcess delete -id` is a valid command and takes `d` as value of -i flag
	// `akcess delete -id abc` is also valid and value of  -i flag is d and abc id discarded
	// Removing id as required so that delete all flag can work.
	//deleteCmd.MarkFlagRequired("id")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: fmt.Sprintf("Print the version of %s", utils.Name),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(VERSION)
	},
}
