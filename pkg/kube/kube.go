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

package kube

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	v1 "k8s.io/api/certificates/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	cmdcreate "k8s.io/kubectl/pkg/cmd/create"

	"github.com/viveksinghggits/akcess/pkg/store"
	"github.com/viveksinghggits/akcess/pkg/utils"
)

type Client struct {
	KubeClient kubernetes.Interface
}

func NewClient(config *rest.Config) (*Client, error) {
	client, err := utils.KubeClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "Creating kubernetes client")
	}

	return &Client{
		KubeClient: client,
	}, nil
}

func (c *Client) CreateCSR(csr *v1.CertificateSigningRequest) (*v1.CertificateSigningRequest, error) {
	return c.KubeClient.CertificatesV1().CertificateSigningRequests().Create(context.Background(), csr, metav1.CreateOptions{})

}

func (c *Client) CreateRole(r *rbacv1.Role) (*rbacv1.Role, error) {
	return c.KubeClient.RbacV1().Roles(r.Namespace).Create(context.Background(), r, metav1.CreateOptions{})
}

func (c *Client) CreateRoleBinding(rb *rbacv1.RoleBinding) (*rbacv1.RoleBinding, error) {
	return c.KubeClient.RbacV1().RoleBindings(rb.Namespace).Create(context.Background(), rb, metav1.CreateOptions{})
}

func RoleObject(o *utils.AllowOptions, id uuid.UUID) (*rbacv1.Role, error) {
	role := &rbacv1.Role{
		// this is ok because we know exactly how we want to be serialized
		TypeMeta: metav1.TypeMeta{APIVersion: rbacv1.SchemeGroupVersion.String(), Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", utils.Name),
			Namespace:    o.Namespace,
			Annotations: map[string]string{
				utils.ResourceAnnotationKey: id.String(),
			},
		},
	}

	rules, err := generateResourcePolicyRules(o.Mapper, o.Verbs, o.Resources, o.ResourceNames, []string{})
	if err != nil {
		return nil, err
	}
	role.Rules = rules

	return role, nil
}

func CSRObject(csr []byte, duration int32, id uuid.UUID) *v1.CertificateSigningRequest {
	// The spec.expirationSeconds field was added in Kubernetes v1.22.
	// Earlier versions of Kubernetes do not honor this field. Kubernetes
	// API servers prior to v1.22 will silently drop this field when the object is created.
	durationSeconds := duration * 60
	csrObject := &v1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", utils.Name, rand.String(5)),
			Annotations: map[string]string{
				utils.ResourceAnnotationKey: id.String(),
			},
		},
		Spec: v1.CertificateSigningRequestSpec{
			Request:           csr,
			SignerName:        v1.KubeAPIServerClientSignerName,
			Usages:            []v1.KeyUsage{v1.UsageClientAuth},
			ExpirationSeconds: &durationSeconds,
		},
	}
	return csrObject
}

func generateResourcePolicyRules(mapper meta.RESTMapper, verbs []string, resources []cmdcreate.ResourceOptions, resourceNames []string, nonResourceURLs []string) ([]rbacv1.PolicyRule, error) {
	// groupResourceMapping is a apigroup-resource map. The key of this map is api group, while the value
	// is a string array of resources under this api group.
	// E.g.  groupResourceMapping = {"extensions": ["replicasets", "deployments"], "batch":["jobs"]}
	groupResourceMapping := map[string][]string{}

	// This loop does the following work:
	// 1. Constructs groupResourceMapping based on input resources.
	// 2. Prevents pointing to non-existent resources.
	// 3. Transfers resource short name to long name. E.g. rs.extensions is transferred to replicasets.extensions
	for _, r := range resources {
		resource := schema.GroupVersionResource{Resource: r.Resource, Group: r.Group}
		groupVersionResource, err := mapper.ResourceFor(schema.GroupVersionResource{Resource: r.Resource, Group: r.Group})
		if err == nil {
			resource = groupVersionResource
		}

		if len(r.SubResource) > 0 {
			resource.Resource = resource.Resource + "/" + r.SubResource
		}
		if !utils.ArrayContains(groupResourceMapping[resource.Group], resource.Resource) {
			groupResourceMapping[resource.Group] = append(groupResourceMapping[resource.Group], resource.Resource)
		}
	}

	// Create separate rule for each of the api group.
	rules := []rbacv1.PolicyRule{}
	for _, g := range sets.StringKeySet(groupResourceMapping).List() {
		rule := rbacv1.PolicyRule{}
		rule.Verbs = verbs
		rule.Resources = groupResourceMapping[g]
		rule.APIGroups = []string{g}
		rule.ResourceNames = resourceNames
		rules = append(rules, rule)
	}

	if len(nonResourceURLs) > 0 {
		rule := rbacv1.PolicyRule{}
		rule.Verbs = verbs
		rule.NonResourceURLs = nonResourceURLs
		rules = append(rules, rule)
	}

	return rules, nil
}

func RoleBindingObject(roleName, userName, ns string, id uuid.UUID) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", utils.Name),
			Namespace:    ns,
			Annotations: map[string]string{
				utils.ResourceAnnotationKey: id.String(),
			},
		},
		RoleRef: rbacv1.RoleRef{
			Name: roleName,
			Kind: "Role",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind: rbacv1.UserKind,
				Name: userName,
			},
		},
	}
}

func (c *Client) ValidateNamespace(ns string) error {
	_, err := c.KubeClient.CoreV1().Namespaces().Get(context.Background(), ns, metav1.GetOptions{})
	return err
}

func DeleteResources(id string) error {
	// accept context from parent
	ctx := context.Background()
	// create kubernetes client
	config, _, err := utils.Config("")
	if err != nil {
		return errors.Wrap(err, "Creating rest.config object")
	}

	client, err := utils.KubeClient(config)
	if err != nil {
		return errors.Wrap(err, "Creating kubernetes client")
	}

	// read the config file and get the namespace
	s, err := store.NewFileStore()
	if err != nil {
		return errors.Wrap(err, "Creating store instance")
	}
	list, err := s.List()
	if err != nil {
		return errors.Wrap(err, "Calling list from store")
	}
	if err := s.Close(); err != nil {
		return err
	}

	var namespace string
	// get the namespace for the requested ID
	for _, c := range list {
		if c.Id == id {
			namespace = c.Namespace
		}
	}

	// what if the namespace is not found because of certain reason

	// we can use dynamic clients and have common utility to delete these resources
	csr, err := client.CertificatesV1().CertificateSigningRequests().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, c := range csr.Items {
		if val, ok := c.Annotations[utils.ResourceAnnotationKey]; ok {
			if val == id {
				// delete this CSR object
				if err = client.CertificatesV1().CertificateSigningRequests().Delete(ctx, c.Name, *&metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}

	roles, err := client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for _, r := range roles.Items {
		if val, ok := r.Annotations[utils.ResourceAnnotationKey]; ok {
			if val == id {
				if err = client.RbacV1().Roles(namespace).Delete(ctx, r.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}

	roleBindings, err := client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for _, rb := range roleBindings.Items {
		if val, ok := rb.Annotations[utils.ResourceAnnotationKey]; ok {
			if val == id {
				if err = client.RbacV1().RoleBindings(namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{}); err != nil {
					return err
				}
			}
		}
	}

	// delete the entry from the config file
	s, err = store.NewFileStore()
	if err != nil {
		return err
	}

	if err := s.DeleteWithID(id); err != nil {
		return err
	}
	return s.Close()
}
