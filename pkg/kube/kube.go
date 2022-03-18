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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/viveksinghggits/akcess/pkg/store"
	"github.com/viveksinghggits/akcess/pkg/utils"
)

type Client struct {
	KubeClient kubernetes.Interface
	DynClient  dynamic.Interface
}

func NewClient(config *rest.Config) (*Client, error) {
	client, err := utils.KubeClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "Creating kubernetes client")
	}

	dyn, err := utils.DynClient(config)
	if err != nil {
		return nil, errors.Wrap(err, "Creating dynamic client")
	}

	return &Client{
		KubeClient: client,
		DynClient:  dyn,
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

func DeleteResources(id, kubeConfigFlag string) error {
	// accept context from parent
	ctx := context.Background()
	// create kubernetes client
	config, _, err := utils.Config(kubeConfigFlag)
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
