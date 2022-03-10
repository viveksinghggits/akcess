/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdcreate "k8s.io/kubectl/pkg/cmd/create"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"

	"github.com/viveksinghggits/akcess/pkg/allow"
	"github.com/viveksinghggits/akcess/pkg/kube"
	"github.com/viveksinghggits/akcess/pkg/store"
	"github.com/viveksinghggits/akcess/pkg/utils"
)

var rootCmd = &cobra.Command{
	Use:   utils.Name,
	Short: "Create kubeconfig file with specified fine-grained authorization",
	Long:  "",
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var (
	options       = &utils.AllowOptions{}
	res           = []string{}
	delIdentifier string
	// VERSION will be overridden by ldflags when we build the project using goreleaser
	VERSION = "DEV"
)

func init() {
	rootCmd.AddCommand(versionCmd, allowCmd, listCmd, deleteCmd)

	allowCmd.Flags().StringSliceVarP(&res, "resource", "r", []string{}, "Resources/subresource to allow access on")
	allowCmd.Flags().StringSliceVarP(&options.Verbs, "verb", "v", []string{}, "Allowed verbs")
	allowCmd.Flags().StringVarP(&options.KubeConfigPath, "kubeconfig", "k", "", "Path to kubeconfig file")
	allowCmd.Flags().StringVarP(&options.Namespace, "namespace", "n", "default", "Namespace of the resource")
	allowCmd.Flags().StringSliceVarP(&options.ResourceNames, "resource-name", "", []string{}, "Resource names to allow access on")
	allowCmd.Flags().Int32VarP(&options.ValidFor, "for", "f", 86400, "Duration the access will be allowed for (in minutes), for example --for 10. Defaults to 1 day")
	// required flags for allow command
	allowCmd.MarkFlagRequired("resource")
	allowCmd.MarkFlagRequired("verb")

	deleteCmd.Flags().StringVarP(&delIdentifier, "id", "i", "", "Id for which the k8s resources should be deleted. Can be figured out from list command")
	// required flags for delete command
	deleteCmd.MarkFlagRequired("id")
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: fmt.Sprintf("Print the version of %s", utils.Name),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(VERSION)
	},
}

var allowCmd = &cobra.Command{
	Use:   "allow",
	Short: "Allow the access to the resources",
	RunE: func(cmd *cobra.Command, args []string) error {
		deDuplicateValues(cmd, options)

		err := validateArguments(options)
		if err != nil {
			return err
		}

		id := uuid.New()
		conf := store.NewAkcessConfig(id.String(), options.Namespace)

		// init store
		// run this in a go routine
		s, err := store.NewFileStore()
		if err != nil {
			return errors.Wrap(err, "initialising filestore")
		}

		if err := s.Write(conf); err != nil {
			return fmt.Errorf("writing config to the filestore, %s\n", err.Error())
		}

		if err = s.Close(); err != nil {
			return errors.Wrap(err, "closing the filestore")
		}

		return allow.Access(options, id)
	},
}

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

var deleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete the kubernetes resources that were made specific allow command",
	RunE: func(cmd *cobra.Command, args []string) error {
		return kube.DeleteResources(delIdentifier)
	},
}

func validateArguments(o *utils.AllowOptions) error {
	if len(o.Verbs) == 0 {
		return fmt.Errorf("atleast one verb must be specified")
	}

	// check supported verbs
	for _, v := range o.Verbs {
		if !utils.ArrayContains(utils.ValidResourceVerbs, v) {
			return fmt.Errorf("verb %s is not supported\n", v)
		}
	}

	// validate resources
	if len(o.Resources) == 0 {
		return fmt.Errorf("at least one resource must be specified")
	}

	for _, r := range o.Resources {
		if len(r.Resource) == 0 {
			return fmt.Errorf("resource must be specified if apiGroup/subresource specified")
		}

		if r.Resource == "*" {
			return nil
		}

		resource := schema.GroupVersionResource{Resource: r.Resource, Group: r.Group}
		groupVersionResource, err := o.Mapper.ResourceFor(schema.GroupVersionResource{Resource: r.Resource, Group: r.Group})
		if err == nil {
			resource = groupVersionResource
		}
		for _, v := range o.Verbs {
			if groupResources, ok := utils.SpecialVerbs[v]; ok {
				match := false
				for _, extra := range groupResources {
					if resource.Resource == extra.Resource && resource.Group == extra.Group {
						match = true
						err = nil
						break
					}
				}
				if !match {
					return fmt.Errorf("can not perform '%s' on '%s' in group '%s'", v, resource.Resource, resource.Group)
				}
			}
		}

		if err != nil {
			return err
		}

	}

	if o.ValidFor*60 < 600 {
		return errors.New("Duration (--for) can not be less than 10 minutes")
	}

	return nil
}

func deDuplicateValues(cmd *cobra.Command, o *utils.AllowOptions) {
	// verbs
	verbs := []string{}
	for _, v := range o.Verbs {
		if v == "*" {
			verbs = []string{"*"}
			break
		}

		if !utils.ArrayContains(verbs, v) {
			verbs = append(verbs, v)
		}
	}
	o.Verbs = verbs

	// resources
	for _, r := range res {
		sections := strings.SplitN(r, "/", 2)

		resource := &cmdcreate.ResourceOptions{}
		if len(sections) == 2 {
			resource.SubResource = sections[1]
		}

		parts := strings.SplitN(sections[0], ".", 2)
		if len(parts) == 2 {
			resource.Group = parts[1]
		}
		resource.Resource = parts[0]

		if resource.Resource == "*" && len(parts) == 1 && len(sections) == 1 {
			o.Resources = []cmdcreate.ResourceOptions{*resource}
			break
		}

		o.Resources = append(o.Resources, *resource)
	}

	// Remove duplicate resource names.
	resourceNames := []string{}
	for _, n := range o.ResourceNames {
		if !utils.ArrayContains(resourceNames, n) {
			resourceNames = append(resourceNames, n)
		}
	}
	o.ResourceNames = resourceNames

	// init mapper
	kubeConfigFlags := genericclioptions.NewConfigFlags(true).WithDeprecatedPasswordFlag()
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)

	m, err := cmdutil.NewFactory(matchVersionKubeConfigFlags).ToRESTMapper()
	if err != nil {
		fmt.Printf("error %s\n", err.Error())
	}

	o.Mapper = m
}
