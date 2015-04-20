# Kube-cluster
Scripts to stand up multi-node kubernetes cluster, private docker registry and standalone docker on SLES 12

# Attributions
Inpired by [Running Multi-Node Kubernetes Using Docker](https://github.com/GoogleCloudPlatform/kubernetes/blob/master/docs/getting-started-guides/docker-multinode.md)

## Environments

* SLES 12.0 x86_64 [Just Enough OS JeOS built using SuSe Studio](https://susestudio.com)
* Kubernetes v0.14.2
* Etcd
* Docker v1.6
* Flannel v0.3.0

## Usage
```
kubernetes.bash master
kubernetes.bash slave 1
kubernetes.bash registry
kubernetes.bash docker 1
kubernetes.bash clean
```
## Note

This script has been hardcoded to create no more than 2 kubernetes slave nodes, to create more you will need to define them first.
Addtionally you can stand up 1 kubernetes master nodes and 1 private docker registry and 1 standalone docker instance.

## Future work
* Enhance the script to run kunernetes master and slave components outside docker.
* Upgrade to Kubernetes v0.15.0
