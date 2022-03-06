## Akcess

`akcess` is a command-line utility that can be used to share very fine-grained access to your Kubernetes
cluster with other teams.

```
» akcess --help
Create kubeconfig file with specified fine-grained authorization

Usage:
  akcess [flags]
  akcess [command]

Available Commands:
  allow       Allow the access to the resources
  completion  Generate the autocompletion script for the specified shell
  delete      Delete the kubernetes resources that were made speicifc allow command
  help        Help about any command
  list        List the number of times we ran the allow command
  version     Print the version of akcess

Flags:
  -h, --help   help for akcess

Use "akcess [command] --help" for more information about a command.
```


## Use cases

Consider a scenario where you are running an application in your Kubernetes cluster that is failing because
of a certain reason and the other (dev) team is asking for permissions to see the logs of that application.

In most of the cases, you wouldn't give the `admin` access to your Kubernetes cluster, instead, you can use
`akcess` to generate `kubeconfig` file that would allow other teams, for example, to just access logs of that
particular application (pod).

```
» akcess allow --verb get --resource pods,pods/log -n <namespace>
```

### Specifying duration

If you are on Kubernetes cluster version 1.22 or greater than it, you can also specify how much time this access
should be allowed for using the below command

```
# value of --for is in minutes and can not be less than 10
» akcess allow --verb get --resource pods,pods/log -n <namespace> --for 10
```

## Installing `akcess`

### Linux

### Windows

## Examples

- Allow access to get pods from `default` namespace

```
» akcess allow --verb list --resource pods
```
- Allow access to see logs of pod with name `nginx` in `test` namespace

```
» akcess allow --verb get,list --resource pods,pods/log -n test
```

You can also directy redirect the output of above commands to a file, that can be set at `KUBECONFIG` env var.
```
» akcess allow --verb get,list --resource pods,pods/log -n test > logsconfig
» export KUBECONFIG=logsconfig
```

## How does it work

`akcess` creates respective RBAC (Role, RoleBinding) and CSR resources using the resources and verbs that are
specified in the `akcess allow` command.

Whenever we create a Kubernetes resource, we annotate it with a key `allow.akcess.id` and value to be a `UUID`.
The set of resources that have been created or the number of time `akcess allow` has been run can be figured
out by running

```
» akcess list
- id: ee022ab3-246f-4a6d-bd53-e04ae90cc1d9
  createdAt: 2022-03-06T12:03:42.171995731+01:00
  namespace: test
- id: 818e4e6f-4be9-41a2-9f8b-de4247626d16
  createdAt: 2022-03-06T12:12:17.884823402+01:00
  namespace: default
```

To delete `Kubernetes` resources for a specific run we can run

```
» akcess delete --id ee022ab3-246f-4a6d-bd53-e04ae90cc1d9
```

