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
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
	certv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apirand "k8s.io/apimachinery/pkg/util/rand"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/viveksinghggits/akcess/pkg/kube"
	"github.com/viveksinghggits/akcess/pkg/utils"
)

func Access(o *utils.AllowOptions, id uuid.UUID) error {
	commonName := fmt.Sprintf("%s-%s", utils.Name, apirand.String(5))

	key, err := privateKey()
	if err != nil {
		return errors.Wrap(err, "Getting private key")
	}

	csr, err := csrForPrivateKey(key, commonName)
	if err != nil {
		return errors.Wrap(err, "Generating CSR for private key")
	}

	config, clientconfig, err := utils.Config(o.KubeConfigPath)
	if err != nil {
		return errors.Wrap(err, "Creating rest.config object")
	}

	k, err := kube.NewClient(config)
	if err != nil {
		return err
	}

	// validate if namespace is available
	if err := k.ValidateNamespace(o.Namespace); err != nil {
		return errors.Wrapf(err, "namespace %s was not found", o.Namespace)
	}

	// csr object from csr bytes
	csrObject := kube.CSRObject(csr, o.ValidFor, id)

	// create CSR Kubernetes object
	c, err := k.CreateCSR(csrObject)
	if err != nil {
		return errors.Wrap(err, "Creating CSR kubernetes object")
	}

	// approve CSR
	csrObject.Status.Conditions = append(csrObject.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         v1.ConditionTrue,
		Reason:         "Certificate wa approved by akcess",
		Message:        "Certificate was approved",
		LastUpdateTime: metav1.Time{Time: time.Now()},
	})

	// accept context from parent
	ctx := context.Background()
	_, err = k.KubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, c.Name, csrObject, metav1.UpdateOptions{})
	if err != nil {
		return errors.Wrap(err, "Approving CertificateSigningRequest")
	}

	// create role and rolebinding
	r, err := kube.RoleObject(o, id)
	if err != nil {
		return errors.Wrap(err, "error getting role object")
	}

	roleObj, err := k.CreateRole(r)
	if err != nil {
		return errors.Wrap(err, "creating role object")
	}

	// role binding
	rb := kube.RoleBindingObject(roleObj.Name, commonName, o.Namespace, id)
	_, err = k.CreateRoleBinding(rb)
	if err != nil {
		return errors.Wrap(err, "Creating rolebinding object")
	}

	// get csr again, so that we can get the certificate from status
	csrOp, err := k.KubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, c.Name, metav1.GetOptions{})
	if err != nil {
		return errors.Wrap(err, "Getting CSR to fetch status.Certificate")
	}

	// Generate KubeConfig file
	return outputKubeConfig(clientconfig, key, csrOp.Status.Certificate, commonName)
}

func privateKey() (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errors.Wrap(err, "Generating priavte key")
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

func outputKubeConfig(config *clientcmdapi.Config, key *rsa.PrivateKey, cert []byte, username string) error {
	name, cluster, err := clusterDetails(config)
	if err != nil {
		return errors.Wrap(err, "getting cluster details")
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
		return errors.Wrap(err, "converting generated config to yaml")
	}
	fmt.Fprint(os.Stdout, string(out))
	return nil
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
