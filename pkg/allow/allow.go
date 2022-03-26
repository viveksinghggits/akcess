package allow

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	certv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apirand "k8s.io/apimachinery/pkg/util/rand"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	cmdcreate "k8s.io/kubectl/pkg/cmd/create"

	"github.com/viveksinghggits/akcess/pkg/kube"
	"github.com/viveksinghggits/akcess/pkg/utils"
)

var (
	certificateWaitTimeout       = 30 * time.Second
	certificateWaitPollInternval = 1 * time.Second
)

type AllowOptions struct {
	Resources          []cmdcreate.ResourceOptions
	Verbs              []string
	ResourceNames      []string
	Labels             []string
	Namespace          string
	KubeConfigPath     string
	ValidFor           int32
	SubResourcePresent bool
	Mapper             meta.RESTMapper
	Clients            kube.Client
}

func Access(o *AllowOptions, id uuid.UUID) ([]byte, error) {
	commonName := fmt.Sprintf("%s-%s", utils.Name, apirand.String(5))

	key, err := privateKey()
	if err != nil {
		return nil, errors.Wrap(err, "Getting private key")
	}

	csr, err := csrForPrivateKey(key, commonName)
	if err != nil {
		return nil, errors.Wrap(err, "Generating CSR for private key")
	}

	_, clientconfig, err := utils.Config(o.KubeConfigPath)
	if err != nil {
		return nil, errors.Wrap(err, "Creating rest.config object")
	}

	// validate if namespace is available
	if err := o.Clients.ValidateNamespace(o.Namespace); err != nil {
		return nil, errors.Wrapf(err, "namespace %s was not found", o.Namespace)
	}

	// csr object from csr bytes
	csrObject := kube.CSRObject(csr, o.ValidFor, id)

	// create CSR Kubernetes object
	c, err := o.Clients.CreateCSR(csrObject)
	if err != nil {
		return nil, errors.Wrap(err, "Creating CSR kubernetes object")
	}

	// approve CSR
	csrObject.Status.Conditions = append(csrObject.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         v1.ConditionTrue,
		Reason:         "Certificate was approved by akcess",
		Message:        "Certificate was approved",
		LastUpdateTime: metav1.Time{Time: time.Now()},
	})

	// accept context from parent
	ctx := context.Background()
	_, err = o.Clients.KubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, c.Name, csrObject, metav1.UpdateOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Approving CertificateSigningRequest")
	}

	// wait for certificate field to be generated in CSR's status.certificate field
	err = wait.Poll(certificateWaitPollInternval, certificateWaitTimeout, func() (done bool, err error) {
		csr, err := o.Clients.KubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, c.Name, metav1.GetOptions{})
		if string(csr.Status.Certificate) != "" {
			return true, nil
		}

		return false, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "waiting for CSR certificate to be generated")
	}

	// create role and rolebinding
	r, err := RoleObject(o, id)
	if err != nil {
		return nil, errors.Wrap(err, "error getting role object")
	}

	roleObj, err := o.Clients.CreateRole(r)
	if err != nil {
		return nil, errors.Wrap(err, "creating role object")
	}

	// role binding
	rb := kube.RoleBindingObject(roleObj.Name, commonName, o.Namespace, id)
	_, err = o.Clients.CreateRoleBinding(rb)
	if err != nil {
		return nil, errors.Wrap(err, "Creating rolebinding object")
	}

	// get csr again, so that we can get the certificate from status
	csrOp, err := o.Clients.KubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, c.Name, metav1.GetOptions{})
	if err != nil {
		return nil, errors.Wrap(err, "Getting CSR to fetch status.Certificate")
	}

	// Generate KubeConfig file
	return outputKubeConfig(clientconfig, key, csrOp.Status.Certificate, commonName)
}

func privateKey() (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "Generating private key")
	}

	return k, nil
}

func csrForPrivateKey(key *rsa.PrivateKey, commonName string) ([]byte, error) {
	csrReq := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Temp. Org"},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrReq, key)
	if err != nil {
		return nil, errors.Wrap(err, "Creating certificate request")
	}

	csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csr, nil
}

func outputKubeConfig(config *clientcmdapi.Config, key *rsa.PrivateKey, cert []byte, username string) ([]byte, error) {
	name, cluster, err := clusterDetails(config)
	if err != nil {
		return nil, errors.Wrap(err, "getting cluster details")
	}

	c := utils.KubeConfig{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: utils.Clusters{
			0: {
				Cluster: utils.Cluster{
					CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte(cluster.CertificateAuthorityData)),
					Server:                   config.Clusters[name].Server,
				},
				Name: name,
			},
		},
		Contexts: utils.Contexts{
			0: {
				Context: utils.Context{
					Cluster: name,
					User:    username,
				},
				Name: "test-context",
			},
		},
		CurrentContext: "test-context",
		Users: utils.Users{
			0: {
				User: utils.User{
					ClientCertificateData: base64.StdEncoding.EncodeToString(cert),
					ClientKeyData:         base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})),
				},
				Name: username,
			},
		},
	}

	out, err := yaml.Marshal(c)
	if err != nil {
		return nil, errors.Wrap(err, "converting generated config to yaml")
	}

	return out, nil
}

func clusterDetails(c *clientcmdapi.Config) (string, *clientcmdapi.Cluster, error) {
	currContext := c.CurrentContext

	var cluster string
	// figure out server name
	for k, v := range c.Contexts {
		if currContext == k {
			cluster = v.Cluster
			break
		}
	}

	if len(cluster) == 0 {
		return "", nil, errors.New("Server not found for current context")
	}

	for k, v := range c.Clusters {
		if k == cluster {
			return cluster, v, nil
		}
	}

	return "", nil, errors.New("Cluster from context was not found in clusters")
}

func RoleObject(o *AllowOptions, id uuid.UUID) (*rbacv1.Role, error) {

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
