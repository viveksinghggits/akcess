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

package utils

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Cluster holds the cluster data
type Cluster struct {
	CertificateAuthorityData string `yaml:"certificate-authority-data"`
	Server                   string `yaml:"server"`
}

//Clusters hold an array of the clusters that would exist in the config file
type Clusters []struct {
	Cluster Cluster `yaml:"cluster"`
	Name    string  `yaml:"name"`
}

//Context holds the cluster context
type Context struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

//Contexts holds an array of the contexts
type Contexts []struct {
	Context Context `yaml:"context"`
	Name    string  `yaml:"name"`
}

//Users holds an array of the users that would exist in the config file
type Users []struct {
	User User   `yaml:"user"`
	Name string `yaml:"name"`
}

//User holds the user authentication data
type User struct {
	ClientCertificateData string `yaml:"client-certificate-data"`
	ClientKeyData         string `yaml:"client-key-data"`
}

//KubeConfig holds the necessary data for creating a new KubeConfig file
type KubeConfig struct {
	APIVersion     string   `yaml:"apiVersion"`
	Clusters       Clusters `yaml:"clusters"`
	Contexts       Contexts `yaml:"contexts"`
	CurrentContext string   `yaml:"current-context"`
	Kind           string   `yaml:"kind"`
	Preferences    struct{} `yaml:"preferences"`
	Users          Users    `yaml:"users"`
}

var (
	// Valid resource verb list for validation.
	ValidResourceVerbs = []string{"*", "get", "delete", "list", "create", "update", "patch", "watch", "proxy", "deletecollection", "use", "bind", "escalate", "impersonate"}
	SpecialVerbs       = map[string][]schema.GroupResource{
		"use": {
			{
				Group:    "policy",
				Resource: "podsecuritypolicies",
			},
			{
				Group:    "extensions",
				Resource: "podsecuritypolicies",
			},
		},
		"bind": {
			{
				Group:    "rbac.authorization.k8s.io",
				Resource: "roles",
			},
			{
				Group:    "rbac.authorization.k8s.io",
				Resource: "clusterroles",
			},
		},
		"escalate": {
			{
				Group:    "rbac.authorization.k8s.io",
				Resource: "roles",
			},
			{
				Group:    "rbac.authorization.k8s.io",
				Resource: "clusterroles",
			},
		},
		"impersonate": {
			{
				Group:    "",
				Resource: "users",
			},
			{
				Group:    "",
				Resource: "serviceaccounts",
			},
			{
				Group:    "",
				Resource: "groups",
			},
			{
				Group:    "authentication.k8s.io",
				Resource: "userextras",
			},
		},
	}
)

const (
	Name                  = "akcess"
	ResourceAnnotationKey = "allow.akcess.id"
)

func Base64EncodeCSR(c []byte) []byte {
	ret := make([]byte, base64.StdEncoding.EncodedLen(len(c)))
	base64.StdEncoding.Encode(ret, c)
	return ret
}

// Config gets us rest.Config considering the kubeconfig flag provided as kubeConfigFlag
// if not, falls back
// 1. KUBECONFIG env var
// 2. default kubeconfig file location
func Config(kubeConfigFlag string) (*rest.Config, *clientcmdapi.Config, error) {
	kubeConfig := ""
	if kubeConfigFlag == "" {
		// kubeconfig was not provided using -k flag
		// check if KUBECONFIG env var is set
		// otherwise fallback to default kubeconfig location
		kubeEnvVar := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
		if kubeEnvVar != "" {
			kubeConfig = kubeEnvVar

		} else {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, nil, errors.Wrap(err, "Getting user home directory")
			}
			kubeConfig = filepath.Join(home, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
		}
	} else {
		kubeConfig = kubeConfigFlag
	}

	var config *rest.Config
	var err error
	if kubeConfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfig)
	} else {
		config, err = rest.InClusterConfig()
	}

	if err != nil {
		return nil, nil, err
	}

	c, err := clientcmd.LoadFromFile(kubeConfig)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Calling clientcmd.LoadFromFile")
	}

	return config, c, nil
}

func KubeClient(config *rest.Config) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(config)
}

func DynClient(config *rest.Config) (dynamic.Interface, error) {
	return dynamic.NewForConfig(config)
}

func ArrayContains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func FilePath() (string, string) {
	var fileRoot string
	if home, err := os.UserHomeDir(); err == nil {
		fileRoot = home
	} else {
		fileRoot = os.TempDir()
	}
	return fmt.Sprintf("%s/.%s/config", fileRoot, Name), fileRoot
}
