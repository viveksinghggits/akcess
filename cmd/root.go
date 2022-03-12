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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	options       = &allow.AllowOptions{}
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
	allowCmd.Flags().StringSliceVarP(&options.ResourceNames, "resource-name", "", []string{}, "Resource names to allow access on, they are not validated to be present on the cluster")
	allowCmd.Flags().Int32VarP(&options.ValidFor, "for", "f", 86400, "Duration the access will be allowed for (in minutes), for example --for 10. Defaults to 1 day")
	allowCmd.Flags().StringArrayVarP(&options.Labels, "labels", "l", []string{}, "Labels of the resources the specified access should be allowed on. For example, if you want to allow access to see logs of a set of pods that have same labels, instead of specifying all those pods separately using --resource-name field we can just specify label that is common among those resources")
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
		// initialise clients
		config, _, err := utils.Config(options.KubeConfigPath)
		if err != nil {
			return errors.Wrap(err, "Creating rest.config object")
		}
		// clients has k8s typed as well as dynamic client
		clients, err := kube.NewClient(config)
		if err != nil {
			return errors.Wrap(err, "Initialising KubeClient")
		}
		options.Clients = *clients

		// de duplicate the values in the flags
		deDuplicateValues(cmd, options)

		err = validateArguments(options)
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

func validateArguments(o *allow.AllowOptions) error {
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

	if len(o.Labels) != 0 {
		// In the cases where we specified more than one resource for example pods,services
		// and a label key=value. And let's say we got m pod resources with that label and n service
		// resources, specifying that in the role object is going to be challenge.
		// We will have to either create two role objects or create a complicated role object.
		// To simplify the things, we are making sure if we are specifying labels we are just providing
		// one resource
		// BUT if we are specifying log or any other subresource in that case we will have to specify
		// more than once reosource but technially its just one resource for ex pods,pods/log
		// so the condition, becomes if its not subresource and resources are more than one
		if len(o.Resources) > 1 && !o.SubResourcePresent {
			return errors.New("You must specify only one resource (--resource) if you want to use --labels flag")
		}

		// get resource names from labels append that into `--resource-name`
		resFromLabels, err := resourcesFromLabels(o)
		if err != nil {
			return err
		}

		o.ResourceNames = append(o.ResourceNames, resFromLabels...)
	}

	if o.ValidFor*60 < 600 {
		return errors.New("Duration (--for) can not be less than 10 minutes")
	}

	return nil
}

func resourcesFromLabels(o *allow.AllowOptions) ([]string, error) {
	resNames := []string{}
	groupVersionResource, err := o.Mapper.ResourceFor(schema.GroupVersionResource{Resource: o.Resources[0].Resource, Group: o.Resources[0].Group})
	r := o.Clients.DynClient.Resource(
		groupVersionResource,
	)

	u, err := r.List(context.Background(), metav1.ListOptions{
		LabelSelector: strings.Join(o.Labels, ","),
	})
	if err != nil {
		return nil, errors.Wrap(err, "Listing resource name using GVR")
	}

	for _, obj := range u.Items {
		resNames = append(resNames, obj.GetName())
	}

	return resNames, nil
}

func deDuplicateValues(cmd *cobra.Command, o *allow.AllowOptions) {
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
			o.SubResourcePresent = true
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
