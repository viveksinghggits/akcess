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
	"k8s.io/apimachinery/pkg/api/meta"
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
		err = deDuplicateValues(cmd, options)
		if err != nil {
			return errors.Wrap(err, "Deduplicating options and creating resource options from resources")
		}

		err = validateArguments(options)
		if err != nil {
			return err
		}

		id := uuid.New()
		conf := store.NewAkcessConfig(id.String(), options.Namespace)

		// init store
		s, err := store.NewFileStore()
		if err != nil {
			return errors.Wrap(err, "initialising filestore")
		}

		// should we do this after things are done
		// run this in a go routine
		if err := s.Write(conf); err != nil {
			return fmt.Errorf("writing config to the filestore, %s\n", err.Error())
		}

		if err = s.Close(); err != nil {
			return errors.Wrap(err, "closing the filestore")
		}

		kubeConfig, err := allow.Access(options, id)
		if err != nil {
			return err
		}

		_, err = fmt.Fprint(os.Stdout, string(kubeConfig))
		return err
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

func deDuplicateValues(cmd *cobra.Command, o *allow.AllowOptions) error {
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
	o.Resources, o.SubResourcePresent = ResourceOptionsFromResources(res)

	// Remove duplicate resource names.
	resourceNames := []string{}
	for _, n := range o.ResourceNames {
		if !utils.ArrayContains(resourceNames, n) {
			resourceNames = append(resourceNames, n)
		}
	}
	o.ResourceNames = resourceNames
	var err error
	o.Mapper, err = InitMapper()
	if err != nil {
		return err
	}
	return nil
}

func InitMapper() (meta.RESTMapper, error) {
	kubeConfigFlags := genericclioptions.NewConfigFlags(true).WithDeprecatedPasswordFlag()
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(kubeConfigFlags)

	m, err := cmdutil.NewFactory(matchVersionKubeConfigFlags).ToRESTMapper()
	if err != nil {
		return nil, err
	}

	return m, nil
}

// ResourceOptionsFromResources gets us cmdcreate.ResourceOptions for resources that have been specified
// as --resource flag to `allow akcess`
// it also returns second value that specified if there are sub resources present in the passed resources
func ResourceOptionsFromResources(resources []string) ([]cmdcreate.ResourceOptions, bool) {
	options := []cmdcreate.ResourceOptions{}
	var subResourcePresent bool
	for _, r := range resources {
		sections := strings.SplitN(r, "/", 2)

		resource := &cmdcreate.ResourceOptions{}
		if len(sections) == 2 {
			subResourcePresent = true
			resource.SubResource = sections[1]
		}

		parts := strings.SplitN(sections[0], ".", 2)
		if len(parts) == 2 {
			resource.Group = parts[1]
		}
		resource.Resource = parts[0]

		if resource.Resource == "*" && len(parts) == 1 && len(sections) == 1 {
			options = []cmdcreate.ResourceOptions{*resource}
			break
		}

		options = append(options, *resource)
	}
	return options, subResourcePresent
}
