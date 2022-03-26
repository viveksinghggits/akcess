package e2e

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/kubectl/pkg/cmd/auth"

	"github.com/viveksinghggits/akcess/cmd"
	"github.com/viveksinghggits/akcess/pkg/allow"
	"github.com/viveksinghggits/akcess/pkg/kube"
	"github.com/viveksinghggits/akcess/pkg/utils"
)

func Test(t *testing.T) {
	TestingT(t)
}

type E2ETestSuite struct {
	clients kube.Client
	mapper  meta.RESTMapper
}

var _ = Suite(&E2ETestSuite{})

func (e *E2ETestSuite) SetUpSuite(c *C) {
	config, _, err := utils.Config("")
	c.Assert(err, IsNil)

	kubeClient, err := utils.KubeClient(config)
	c.Assert(err, IsNil)

	dynClient, err := utils.DynClient(config)
	c.Assert(err, IsNil)

	e.clients = kube.Client{
		KubeClient: kubeClient,
		DynClient:  dynClient,
	}

	e.mapper, err = cmd.InitMapper()
	c.Assert(err, IsNil)
}

// this test right now mimics `k auth can-i` to check if we are able to do something
// that we didn't specify in `akcess allow`.
// Instead we can also consider using k auth can-i --list
// to make sure we are able to do just what we have specified in akcess allow
func (e *E2ETestSuite) TestAkcess(c *C) {
	c.Log("Running E2E test")
	for _, tc := range []struct {
		verbs             []string
		resources         []string
		namespace         string
		checkVerb         string
		checkRes          string
		shouldItBeAllowed bool
		comment           string
	}{
		{
			verbs:             []string{"get"},
			resources:         []string{"pods"},
			namespace:         "default",
			checkVerb:         "delete",
			checkRes:          "service",
			shouldItBeAllowed: false,
		},
		{
			verbs:             []string{"get", "list"},
			resources:         []string{"pods"},
			namespace:         "default",
			checkVerb:         "delete",
			checkRes:          "service",
			shouldItBeAllowed: false,
		},
		{
			verbs:             []string{"get"},
			resources:         []string{"pods", "ingresses"},
			namespace:         "default",
			checkVerb:         "delete",
			checkRes:          "service",
			shouldItBeAllowed: false,
		},
		{
			verbs:             []string{"get"},
			resources:         []string{"pods", "ingresses"},
			namespace:         "default",
			checkVerb:         "get",
			checkRes:          "ingresses",
			shouldItBeAllowed: true,
		},
		{
			verbs:             []string{"get"},
			resources:         []string{"pods", "ingresses"},
			namespace:         "default",
			checkVerb:         "get",
			checkRes:          "pods",
			shouldItBeAllowed: true,
		},
		{
			verbs:             []string{"get"},
			resources:         []string{"pods", "pods/logs"},
			namespace:         "default",
			checkVerb:         "get",
			checkRes:          "pods",
			shouldItBeAllowed: true,
		},
		{
			verbs:             []string{"get"},
			resources:         []string{"pods", "pods/logs"},
			namespace:         "default",
			checkVerb:         "get",
			checkRes:          "pods/logs",
			shouldItBeAllowed: true,
		},
		{
			verbs:             []string{"get"},
			resources:         []string{"pods", "pods/logs"},
			namespace:         "default",
			checkVerb:         "list",
			checkRes:          "pods",
			shouldItBeAllowed: false,
		},
	} {
		id := uuid.New()

		options := &allow.AllowOptions{
			ValidFor: 86400,
		}
		options.Clients = e.clients
		options.Verbs = tc.verbs
		options.Resources, options.SubResourcePresent = cmd.ResourceOptionsFromResources(tc.resources)
		options.Namespace = tc.namespace
		var err error
		options.Mapper = e.mapper

		// generate the Kubeconfig file using the akcess allow command for the specified verb and resources
		kubeConfig, err := allow.Access(options, id)
		c.Assert(err, IsNil)

		tempDir := c.MkDir()
		err = os.WriteFile(e.configLoc(tempDir), kubeConfig, 777)
		c.Assert(err, IsNil)

		// set the `KUBECONFIG` env var to newly generated kubeconfig file
		c.Assert(os.Setenv("KUBECONFIG", e.configLoc(tempDir)), IsNil)

		// run `kubectl auth can-i` to check if we are able to do things
		// that are not specified above
		// we will have to create new client using the new config that was created
		config, _, err := utils.Config("")
		c.Assert(err, IsNil)

		k, err := utils.KubeClient(config)
		c.Assert(err, IsNil)

		checkResources, _ := cmd.ResourceOptionsFromResources([]string{tc.checkRes})

		reosurce := schema.GroupVersionResource{Group: checkResources[0].Group, Resource: checkResources[0].Resource}
		gvr, err := e.mapper.ResourceFor(reosurce)
		c.Assert(err, IsNil)

		canIOptions := auth.CanIOptions{
			Namespace: tc.namespace,
			Verb:      tc.checkVerb,
			Resource: schema.GroupVersionResource{
				Group:    gvr.Group,
				Resource: checkResources[0].Resource,
			},
			Subresource: checkResources[0].SubResource,
			AuthClient:  k.AuthorizationV1(),
			// we can also use &bytes.Buffer{} if we wan to use this
			// but for now we are just going to discard it
			IOStreams: genericclioptions.NewTestIOStreamsDiscard(),
		}
		can, err := canIOptions.RunAccessCheck()
		c.Assert(err, IsNil)
		c.Assert(can, Equals, tc.shouldItBeAllowed)
	}
}

func (e *E2ETestSuite) configLoc(tempDir string) string {
	return fmt.Sprintf("%s/%s", tempDir, "config")
}
