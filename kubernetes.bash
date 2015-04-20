#!/bin/bash

# usage:
# kubernetes.bash master
# kubernetes.bash slave 1
# kubernetes.bash registry
# kubernetes.bash docker 1
# kubernetes.bash clean

# NOTE:
# This script has been hardcoded to create no more than 2 kubernetes
# slave nodes, to create more you will need to define them first.
# Addtionally you can stand up 1 kubernetes master nodes and 1 
# private docker registry and 1 standalone docker instance.

set -o errexit   ## set -e : exit the script if any statement returns a non-true return value

#############################################################
# Defaults
#############################################################

BASEDIR=$(dirname $0)

# bash color
COL_BLUE="\e[0;34m"
COL_GREEN="\e[0;32m"
COL_RED="\e[0;31m"
COL_LIGHTRED="\e[1;31m"
COL_MAGENTA="\e[0;35m"
COL_YELLOW="\e[1;33m"
COL_RESET="\e[0m"

KUBERNETES_VERSION='0.14.2'
ETCD_VERSION='2.0.5.1'
FLANNEL_VERSION='0.3.0'
GO_VERSION='1.4.2'
DOCKER_REGISTRY_VERSION='2.0.0'

http_proxy=http://mpproxy.com:port
https_proxy=$http_proxy
no_proxy=.local,127.0.0.1,10.*,.mydomain.com,.sock

#############################################################
# Home

need_proxy=false
setup_network=true

DEFAULT_GATEWAY='192.168.1.1'
DOMAIN_NAME='kubernetes.com'

DNS_SEARCH='twmi.rr.com'
DNS_NAMESERVERS=(192.168.1.1)

DOCKER_REGISTRY_NAME='fcr'
DOCKER_REGISTRY_IP='192.168.1.14'
DOCKER_REGISTRY_NETMASK='255.255.255.0'
DOCKER_REGISTRY_HOST_PORT='5000'
DOCKER_REGISTRY_CONTAINER_PORT='5000'
DOCKER_REGISTRY_VOLUME='/var/docker'
DOCKER_REGISTRY_CONTAINER_VOLUME='/var/docker'
DOCKER_REGISTRY_INSTALL_DIR='/opt/distribution'

STANDALONE_DOCKER_NAMES=('docker-1')
STANDALONE_DOCKER_IPS=('192.168.1.15')
STANDALONE_DOCKER_NETMASK=('255.255.255.0')
STANDALONE_DOCKER_CERTS_DIR='/opt/docker'

MASTER_NAME='kube-master'
MASTER_IP='192.168.1.10'
MASTER_NETMASK='255.255.255.0'

MINION_NAMES=(kube-minion-1 kube-minion-2 kube-minion-3)
MINION_IPS=(192.168.1.11 192.168.1.12 192.168.1.13)
MINION_NETMASK=(255.255.255.0 255.255.255.0 255.255.255.0)

#############################################################
# BEGIN FUNCTIONS
#############################################################
setup_proxy() {
  if [ "$need_proxy" == true ]; then
    (
    echo "export http_proxy=$http_proxy"
    echo "export https_proxy=$http_proxy"
    echo "export no_proxy=$no_proxy"
    ) > /root/.bash_profile

    source /root/.bash_profile
  fi
}

update_nameservers() {
  local need_restart=false

  if [ "${DNS_SEARCH}" != "" ] && [ ! "$(cat /etc/resolv.conf | grep ${DNS_SEARCH})" ]; then
    echo "search ${DNS_SEARCH}" >>/etc/resolv.conf
    need_restart=true
  fi
  
  for (( i=0; i<${#DNS_NAMESERVERS[@]}; i++)); do
    local nameserver=${DNS_NAMESERVERS[$i]}
    if [ ! "$(cat /etc/resolv.conf | grep ${nameserver})" ]; then
      echo "nameserver ${nameserver}" >>/etc/resolv.conf
      need_restart=true
    fi
  done

  if [ "$need_restart" == true ]; then
    systemctl restart network
  else
    echo -e "${COL_GREEN}Skipped... No changes required ... all is well${COL_RESET}"
  fi
}

setup_network() {
  local need_restart=false

  if [ ! "$(cat /etc/hosts | grep $MASTER_NAME)" ]; then
    echo "$MASTER_IP $MASTER_NAME.$DOMAIN_NAME $MASTER_NAME" >> /etc/hosts
    need_restart=true
  fi

  if [ ! "$(cat /etc/hosts | grep $DOCKER_REGISTRY_NAME)" ]; then
    echo "$DOCKER_REGISTRY_IP $DOCKER_REGISTRY_NAME.$DOMAIN_NAME $DOCKER_REGISTRY_NAME" >> /etc/hosts
    need_restart=true
  fi

  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    local minion=${MINION_NAMES[$i]}
    local minionip=${MINION_IPS[$i]}
    if [ ! "$(cat /etc/hosts | grep $minion)" ]; then
      echo "$minionip $minion.$DOMAIN_NAME $minion" >> /etc/hosts
      need_restart=true
    fi
  done

  # Setup hostname
  if [ ! $(cat /etc/hostname | grep "^\s*${NODE_NAME}.${DOMAIN_NAME}") ]; then
    echo "${NODE_NAME}.${DOMAIN_NAME}" > /etc/hostname
    need_restart=true
  fi

  # Enable wicked's Nanny Daemon
  sed -i 's|<use-nanny>false</use-nanny>|<use-nanny>true</use-nanny>|g' /etc/wicked/common.xml

  # Assign static ip address
  if [ -f /etc/sysconfig/network/ifcfg-eth0 ]; then
    cp /etc/sysconfig/network/ifcfg-eth0 /etc/sysconfig/network/old-ifcfg-eth0
  fi

  if [ ! -f /etc/sysconfig/network/ifcfg-eth0 ] || [ ! "$(cat /etc/sysconfig/network/ifcfg-eth0 | grep ${NODE_IP})" ]; then
    (
      echo "STARTMODE='auto'"
      echo "BOOTPROTO='static'"
      echo "IPADDR='${NODE_IP}'"
      echo "NETMASK='${NODE_NETMASK}'"
      echo "NAME='eth0'"
    ) > /etc/sysconfig/network/ifcfg-eth0
    need_restart=true
  fi

  # Enable ipv4 packet forwarding
  # http://linuxpoison.blogspot.com/2008/01/how-to-enable-ip-forwarding.html
  if [ ! $( cat /etc/sysctl.conf | grep '^\s*net.ipv4.ip_forward') ] || [ $( cat /etc/sysctl.conf | grep '^\s*net.ipv4.ip_forward' | cut -d "=" -f2 ) -ne 1 ]; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    need_restart=true
  fi

  # Setup the default gateway
  if [ ! -f /etc/sysconfig/network/routes ] || [ ! $(cat /etc/sysconfig/network/routes | grep "^\s*default\s*${DEFAULT_GATEWAY}") ]; then
    (
    echo "#https://www.suse.com/documentation/sles-12/book_sle_admin/data/sec_basicnet_manconf.html"
    echo "# --- IPv4 routes in CIDR prefix notation:"
    echo "#Destination         [Gateway]           -     Interface"
    echo "default              ${DEFAULT_GATEWAY}  -     eth0"
    ) > /etc/sysconfig/network/routes
    need_restart=true
  fi

  if [ "$need_restart" == true ]; then
    systemctl restart wickedd.service
    systemctl restart network
    wicked ifup all
  fi
}

setup_repos() {
  if ! zypper lr >/dev/null 2>&1 || [ $( zypper lr | grep -c 'Virtualization\|oss\|openSUSE_13.2_Update' ) -ne 3 ]; then
    zypper ar -f http://download.opensuse.org/repositories/Virtualization/openSUSE_13.2/Virtualization.repo >/dev/null 2>&1
    zypper ar -f http://download.opensuse.org/distribution/13.2/repo/oss/ oss >/dev/null 2>&1  
    zypper ar -f http://download.opensuse.org/update/13.2/openSUSE:13.2:Update.repo >/dev/null 2>&1
    # This only required for to openvswitch overlay network
    #zypper ar -f http://download.opensuse.org/repositories/network/SLE_12/network.repo >/dev/null 2>&1

    # Refresh zypper repos
    zypper --gpg-auto-import-keys refresh
  else
    echo -e "${COL_GREEN}Skipped... No changes required ... all is well${COL_RESET}"
  fi
}

install_docker() {
  if ! which docker >/dev/null 2>&1; then
    zypper -n install docker wget make
    sed -i "s|DOCKER_OPTS=\"\"|DOCKER_OPTS=\"-H unix:///var/run/docker.sock --insecure-registry gcr.io --insecure-registry ${DOCKER_REGISTRY_IP}:${DOCKER_REGISTRY_HOST_PORT}\"|g" /etc/sysconfig/docker
    if [ "$need_proxy" == true ] && [ $( cat /etc/sysconfig/docker | grep -c http_proxy ) -eq 0 ]; then
        (
        echo "http_proxy=$http_proxy"
        echo "HTTP_PROXY=$http_proxy"
        echo "https_proxy=$http_proxy"
        echo "HTTPS_PROXY=$http_proxy"
        echo "no_proxy=$no_proxy"
        echo "export HTTP_PROXY HTTPS_PROXY http_proxy https_proxy no_proxy"
        ) >> /etc/sysconfig/docker
    fi

    systemctl daemon-reload
    systemctl enable docker.service
    systemctl start docker.service
  else
    echo -e "${COL_GREEN}Skipped... No changes required ... all is well${COL_RESET}"
  fi

  until [ $( ps -ef | grep docker.sock | grep -v 'grep' | wc -l ) -gt 0 ]
  do
    echo "Waiting for Docker service to come online"
    sleep 1
  done
  systemctl status docker.service
}

setup_docker_bootstrap() {
  if [ ! "$(ps -ef | grep docker-bootstrap.sock | grep -v 'grep')" ]; then
    local file=/usr/lib/systemd/system/docker-bootstarp.service
    
    (
      echo "[Unit]"
      echo "Description=Docker Bootstrap Application Container Engine"
      echo "Documentation=http://docs.docker.com"
      echo ""
      echo "[Service]"
      echo "Environment=TMPDIR=/var/tmp"
    ) > ${file}

    if [ "$need_proxy" == true ]; then
      (   
        echo "Environment=\"http_proxy=$http_proxy\""
        echo "Environment=\"https_proxy=$http_proxy\""
        echo "Environment=\"no_proxy=$no_proxy\""
      ) >> ${file}
    fi

    (
      echo "MountFlags=slave"
      echo "LimitNOFILE=1048576"
      echo "LimitNPROC=1048576"
      echo "ExecStart=/usr/bin/docker -d -H unix:///var/run/docker-bootstrap.sock --bridge=none --iptables=false --ip-masq=false --graph=/var/lib/docker-bootstrap --pidfile=/var/run/docker-bootstrap.pid"
      echo ""
      echo "[Install]"
      echo "WantedBy=docker-bootstrap.target"
    ) >> ${file}

    systemctl daemon-reload
    systemctl enable docker-bootstarp.service
    systemctl start docker-bootstarp.service

    until [ $( ps -ef | grep docker-bootstrap.sock | grep -v 'grep' | wc -l ) -gt 0 ]
    do
      echo "Waiting for Docker Bootstrap service to come online"
      sleep 1
    done
    systemctl status docker-bootstarp.service
  fi
}

start_etcd() {
  # Startup etcd for flannel and the API server to use
  docker -H unix:///var/run/docker-bootstrap.sock run \
    --net=host \
    -d kubernetes/etcd:${ETCD_VERSION} /usr/local/bin/etcd \
    --addr=127.0.0.1:4001 \
    --bind-addr=0.0.0.0:4001 \
    --data-dir=/var/etcd/data

  rc=$?
  if [ $rc != 0 ]; then 
    echo -e "${COL_RED}Failed start etcd container${COL_RESET}"
    exit $rc
  fi

  until [ $( docker -H unix:///var/run/docker-bootstrap.sock ps | grep "kubernetes/etcd:${ETCD_VERSION}" | grep -c Up ) -gt 0 ]
  do
    echo "Waiting for etcd docker container to come online"
    sleep 1
  done

  # TODO(SPURANAM) this is nasty fixit
  # guess we need to query the state of service inside the container before continuing
  sleep 5

  # Set a CIDR range for flannel
  docker -H unix:///var/run/docker-bootstrap.sock run \
    --net=host \
    kubernetes/etcd:${ETCD_VERSION} etcdctl \
    set /coreos.com/network/config '{ "Network": "10.1.0.0/16" }'

  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed to set CIDR range for flannel"
    exit $rc
  fi
}

setup_flannel() {
  if [ $# -ne 1 ]; then
    echo "You must provide following parameter:"
    echo "1. Is this master/slave node"
  fi

  local NODE_TYPE=$1
  local flannel

  # Bring down Docker to re-configure Docker to use flannel
  systemctl stop docker.service

  # Start the flanneld container
  if [ "$NODE_TYPE" == 'master' ]; then
    # on master etcd is running locally
    flannel=$(docker -H unix:///var/run/docker-bootstrap.sock run -d --net=host --privileged -v /dev/net:/dev/net quay.io/coreos/flannel:${FLANNEL_VERSION})
  else
    # Start flanneld pointed to etcd running on master
    flannel=$(docker -H unix:///var/run/docker-bootstrap.sock run -d --net=host --privileged -v /dev/net:/dev/net quay.io/coreos/flannel:${FLANNEL_VERSION} /opt/bin/flanneld --etcd-endpoints=http://${MASTER_IP}:4001)
  fi

  until [ $( docker -H unix:///var/run/docker-bootstrap.sock ps | grep "quay.io/coreos/flannel:${FLANNEL_VERSION}" | grep -c Up ) -gt 0 ]
  do
    echo "Waiting for flannel docker container to come online"
    sleep 1
  done

  # TODO(SPURANAM) this is nasty fixit
  # guess we need to query the state of service inside the container before continuing
  sleep 5

  # Get the overlay network subnet from flannel
  docker -H unix:///var/run/docker-bootstrap.sock \
    exec $flannel cat /run/flannel/subnet.env > /tmp/subnet.env

  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed get flannel network information"
    exit $rc
  fi

  # Get the flannel subnet
  local FLANNEL_SUBNET=$(cat /tmp/subnet.env | grep FLANNEL_SUBNET | cut -d "=" -f2)

  # Get the flannel overlay network MTU
  local FLANNEL_MTU=$(cat /tmp/subnet.env | grep FLANNEL_MTU | cut -d "=" -f2)

  # Edit the docker configuration to use flannel overlay network instead of the default docker bridge
  sed -i "s|DOCKER_OPTS=\"-H unix:///var/run/docker.sock --insecure-registry gcr.io --insecure-registry ${DOCKER_REGISTRY_IP}:${DOCKER_REGISTRY_HOST_PORT}\"|DOCKER_OPTS=\"-H unix:///var/run/docker.sock --insecure-registry gcr.io --insecure-registry ${DOCKER_REGISTRY_IP}:${DOCKER_REGISTRY_HOST_PORT} --bip=${FLANNEL_SUBNET} --mtu=${FLANNEL_MTU}\"|g" /etc/sysconfig/docker

  # Temporarily disable exit on error
  set +o errexit
  
  # Remove the existing Docker bridge
  /sbin/ifconfig docker0 down
  /sbin/brctl delbr docker0
  rm -f /tmp/subnet.env
  
  # Enable exit on error
  set -o errexit

  # Restart docker
  systemctl daemon-reload
  systemctl start docker.service

  until [ $( ps -ef | grep docker.sock | grep -v 'grep' | wc -l ) -gt 0 ]
  do
    echo "Waiting for Docker service to come online"
    sleep 1
  done

  systemctl status docker.service
}

start_kerbernetes_master() {
  docker run --net=host -d \
    -v /var/run/docker.sock:/var/run/docker.sock  \
    gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION} \
    /hyperkube kubelet \
    --api_servers=http://localhost:8080 \
    --v=2 --address=0.0.0.0 \
    --enable_server \
    --hostname_override=127.0.0.1 \
    --config=/etc/kubernetes/manifests-multi

  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed to start Kubernetes Master container"
    exit $rc
  fi

  until [ $( docker ps | grep "gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION}" | grep kubelet | grep -c Up ) -gt 0 ]
  do
    echo "Waiting for Kubernetes Master docker container to come online"
    sleep 1
  done
}

start_master_service_proxy() {
  docker run -d \
    --net=host \
    --privileged \
    gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION} \
    /hyperkube proxy \
    --master=http://127.0.0.1:8080 \
    --v=2

  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed to start Kubernetes Master Service proxy container"
    exit $rc
  fi

  until [ $( docker ps | grep "gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION}" | grep proxy | grep -c Up ) -gt 0 ]
  do
    echo "Waiting for Kubernetes Master service proxy docker container to come online"
    sleep 1
  done
}

start_kubelet() {
  docker run \
    --net=host \
    -d \
    -v /var/run/docker.sock:/var/run/docker.sock  \
    gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION} \
    /hyperkube kubelet \
    --api_servers=http://${MASTER_IP}:8080 \
    --v=2 \
    --address=0.0.0.0 \
    --enable_server \
    --hostname_override=${NODE_IP}

  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed to start Kubernetes kubelet container"
    exit $rc
  fi
    
  until [ $( docker ps | grep "gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION}" | grep kubelet | grep -c Up ) -gt 0 ]
  do
    echo "Waiting for Kubernetes kubelet docker container to come online"
    sleep 1
  done
}

start_slave_service_proxy() {
  docker run \
    -d \
    --net=host \
    --privileged \
    gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION} \
    /hyperkube proxy \
    --master=http://${MASTER_IP}:8080 \
    --v=2

  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed to start Kubernetes slave Service proxy container"
    exit $rc
  fi

  until [ $( docker ps | grep "gcr.io/google_containers/hyperkube:v${KUBERNETES_VERSION}" | grep proxy | grep -c Up ) -gt 0 ]
  do
    echo "Waiting for Kubernetes slave service proxy docker container to come online"
    sleep 1
  done
}

install_kubectl() {
  if [ ! -f /usr/local/bin/kubectl ]; then
    local url=http://storage.googleapis.com/kubernetes-release/release/v${KUBERNETES_VERSION}/bin/linux/amd64/kubectl
    curl -L $url -o /usr/local/bin/kubectl
    chmod 755 /usr/local/bin/kubectl
  fi
}

add_nodes_cluster() {
  if [ -d /opt/kubernetes/nodes ]; then
    rm -rf /opt/kubernetes/nodes >/dev/null 2>&1
  fi
  mkdir -p /opt/kubernetes/nodes

  for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
    (
      echo "apiVersion: v1beta1"
      echo "externalID: ${MINION_IPS[$i]}"
      echo "hostIP: ${MINION_IPS[$i]}"
      echo "id: ${MINION_IPS[$i]}"
      echo "kind: Node"
      echo "resources:"
      echo "  capacity:"
      echo "    # Adjust these to match your node"
      echo "    cpu: \"2\""
      echo "    memory: 4056348"
    ) > "/opt/kubernetes/nodes/node-$(($i+1)).yaml"
  done
}

register_nodes() {
  FILES=/opt/kubernetes/nodes/*
  for f in $FILES
  do
    echo "Processing $f file..."
    kubectl create -f $f
  done
}

confirm() {
    # call with a prompt string or use a default
    read -r -p "${1:-Are you sure? [y/N]} " response
    case $response in
        [yY][eE][sS]|[yY]) 
            true
            ;;
        *)
            false
            ;;
    esac
}

ask_yes_or_no() {
    read -p "$1 ([y]es or [N]o): "
    case $(echo $REPLY | tr '[A-Z]' '[a-z]') in
        y|yes) echo "yes" ;;
        *)     echo "no" ;;
    esac
}

reset_os() {
  # Temporarily disable exit on error
  set +o errexit
  # stop docker service
  systemctl stop docker-bootstarp.service > /dev/null 2>&1
  systemctl stop docker.service > /dev/null 2>&1
  # remove zypper repos
  zypper -n remove docker wget > /dev/null 2>&1
  zypper rr Virtualization openSUSE_13.2_Update oss > /dev/null 2>&1
  # remove docker configs
  rm /etc/sysconfig/docker > /dev/null 2>&1
  rm /usr/lib/systemd/system/docker-bootstarp.service > /dev/null 2>&1 
  rm /usr/lib/systemd/system/docker.service > /dev/null 2>&1
  rm /var/run/docker-bootstrap.sock > /dev/null 2>&1
  rm /var/run/docker.sock > /dev/null 2>&1
  rm -rf /var/lib/docker > /dev/null 2>&1
  # remove kubernetes nodes definitions
  rm -rf /opt/kubernetes/nodes > /dev/null 2>&1
  # remove kubectl binary
  rm -rf /usr/local/bin/kubectl > /dev/null 2>&1
  # remove bash profile file
  rm -rf /root/.bash_profile > /dev/null 2>&1
  # remove go
  rm -rf /usr/local/go > /dev/null 2>&1
  # remove docker registry
  rm -rf ${DOCKER_REGISTRY_INSTALL_DIR} > /dev/null 2>&1
  # remove docker registry volume
  rm -rf ${DOCKER_REGISTRY_VOLUME} > /dev/null 2>&1
  # enable exit on error
  set -o errexit 
}

install_go() {
  if [ ! -d /usr/local/go ]; then 
    local url=https://storage.googleapis.com/golang/go${GO_VERSION}.linux-amd64.tar.gz
    curl -L ${url} -o /tmp/go${GO_VERSION}.tar.gz
    tar -C /usr/local -xzf /tmp/go${GO_VERSION}.tar.gz
    echo "export PATH=/usr/local/go/bin:$PATH" >> /root/.bash_profile
    source /root/.bash_profile
    rm -f /tmp/go${GO_VERSION}.tar.gz >/dev/null 2>&1
  fi
}

get_docker_registry_source() {
  if [ -d ${DOCKER_REGISTRY_INSTALL_DIR} ]; then
    rm -rf ${DOCKER_REGISTRY_INSTALL_DIR} > /dev/null 2>&1
  fi

  git clone https://github.com/docker/distribution ${DOCKER_REGISTRY_INSTALL_DIR}
  cd ${DOCKER_REGISTRY_INSTALL_DIR}
  git checkout v${DOCKER_REGISTRY_VERSION}
}

build_docker_registry() {
    # Customize the docker registry configuration file
  cat <<EOF > ${DOCKER_REGISTRY_INSTALL_DIR}/cmd/registry/config.yml
version: 0.1
log:
  level: debug
  fields:
    service: registry
    environment: development
storage:
    cache:
        layerinfo: filesystem
    filesystem:
        rootdirectory: ${DOCKER_REGISTRY_CONTAINER_VOLUME}
http:
    addr: :5000
    secret: MyDeepSuperS@@ret2015
    debug:
        addr: localhost:5001
    tls:
        certificate: /go/src/github.com/docker/distribution/certs/server.crt
        key: /go/src/github.com/docker/distribution/certs/server.key
redis:
  addr: localhost:6379
  pool:
    maxidle: 16
    maxactive: 64
    idletimeout: 300s
  dialtimeout: 10ms
  readtimeout: 10ms
  writetimeout: 10ms
notifications:
    endpoints:
        - name: local-8082
          url: http://localhost:5003/callback
          headers:
             Authorization: [Bearer <an example token>]
          timeout: 1s
          threshold: 10
          backoff: 1s
          disabled: true
        - name: local-8083
          url: http://localhost:8083/callback
          timeout: 1s
          threshold: 10
          backoff: 1s
          disabled: true
EOF
  
  # If the image exists then delete it
  local imgid=$(docker images | grep 'secure_registry' | awk '{ print $3}')
  if [ "$imgid" != "" ]; then
    # If the image is in use stop and remove the container
    local conid=$(docker ps | grep 'secure_registry:latest' | awk '{ print $1}')
    if [ "$conid" != "" ]; then
      docker stop ${conid} > /dev/null 2>&1
      docker rm ${conid} > /dev/null 2>&1
    fi
    docker rmi -f ${imgid} > /dev/null 2>&1
  fi

  # Build registry image
  cd ${DOCKER_REGISTRY_INSTALL_DIR}
  docker build -t secure_registry .

  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed to build docker registry image"
    exit $rc
  fi
}

start_docker_registry() {
  if [ ! -d ${DOCKER_REGISTRY_VOLUME} ]; then
    mkdir -p ${DOCKER_REGISTRY_VOLUME}
  fi  
  cd ${BASEDIR}
  docker run -d -v ${DOCKER_REGISTRY_VOLUME}:${DOCKER_REGISTRY_CONTAINER_VOLUME} -p ${DOCKER_REGISTRY_HOST_PORT}:${DOCKER_REGISTRY_CONTAINER_PORT} secure_registry:latest
  
  rc=$?
  if [ $rc != 0 ]; then 
    echo "Failed to start docker registry container"
    exit $rc
  fi
}

gen_ssl_certs() {
  if [ $# -ne 4 ]; then
    echo "You must provide following four (4) parameters"
    echo "1. Type of cert to generate clientserver/serveronly/clientonly"
    echo "2. Location where certs will to stored"
    echo "3. IP address of the node for which this certs belongs"
    echo "4. Hostname of the node for which this certs belongs"
  fi
  
  local CERT_TYPE=$1
  local CERT_DIR=$2
  local CERT_IP=$3
  local CERT_HOSTNAME=$4

  local CLIENT_DIR
  local SERVER_DIR
  local CLIENT_CERT_FILENAME
  local SERVER_CERT_FILENAME

  if [ "$CERT_TYPE" == 'clientserver' ]; then
    CLIENT_DIR="${CERT_DIR}/client"
    SERVER_DIR="${CERT_DIR}/server"
    CLIENT_CERT_FILENAME='client'
    SERVER_CERT_FILENAME="${CERT_HOSTNAME}"
    mkdir -p "${CLIENT_DIR}"
    mkdir -p "${SERVER_DIR}"
  elif [ "$CERT_TYPE" == 'clientonly' ]; then
    CLIENT_DIR="${CERT_DIR}"
    CLIENT_CERT_FILENAME="${CERT_HOSTNAME}"
    mkdir -p "${CLIENT_DIR}"
  elif [ "$CERT_TYPE" == 'serveronly' ]; then
    SERVER_DIR="${CERT_DIR}"
    SERVER_CERT_FILENAME="${CERT_HOSTNAME}"
    mkdir -p "${SERVER_DIR}"
  fi

  tmpdir=$(mktemp -d --tmpdir docker_registry_cacert.XXXXXX)
  trap 'rm -rf "${tmpdir}"' EXIT
  cd "${tmpdir}"

  # TODO: For now, this is a patched tool that makes subject-alt-name work, when
  # the fix is upstream  move back to the upstream easyrsa.  This is cached in GCS
  # but is originally taken from:
  #   https://github.com/brendandburns/easy-rsa/archive/master.tar.gz
  #
  # To update, do the following:
  # curl -o easy-rsa.tar.gz https://github.com/brendandburns/easy-rsa/archive/master.tar.gz
  # gsutil cp easy-rsa.tar.gz gs://kubernetes-release/easy-rsa/easy-rsa.tar.gz
  # gsutil acl ch -R -g all:R gs://kubernetes-release/easy-rsa/easy-rsa.tar.gz
  #
  # Due to GCS caching of public objects, it may take time for this to be widely
  # distributed.
  curl -L -O https://storage.googleapis.com/kubernetes-release/easy-rsa/easy-rsa.tar.gz
  tar xzf easy-rsa.tar.gz
  
  cd easy-rsa-master/easyrsa3
  ./easyrsa init-pki
  #./easyrsa --batch "--req-cn=${CERT_IP}@`date +%s`" build-ca nopass
  ./easyrsa --batch "--req-cn=${CERT_HOSTNAME}.${DOMAIN_NAME}" build-ca nopass
  
  if [ "$CERT_TYPE" == "clientserver" ] || [ "$CERT_TYPE" == "serveronly" ]; then
    ./easyrsa --subject-alt-name=IP:"${CERT_IP}",DNS:"${CERT_HOSTNAME}.${DOMAIN_NAME}" build-server-full "${SERVER_CERT_FILENAME}" nopass
    cp -p pki/ca.crt "${SERVER_DIR}/ca.crt" 
    cp -p pki/private/ca.key "${SERVER_DIR}/ca.key"
    cp -p pki/issued/${SERVER_CERT_FILENAME}.crt "${SERVER_DIR}/server.crt"
    cp -p pki/private/${SERVER_CERT_FILENAME}.key "${SERVER_DIR}/server.key"
  fi
  
  if [ "$CERT_TYPE" == "clientserver" ] || [ "$CERT_TYPE" == "clientonly" ]; then
    ./easyrsa --subject-alt-name=IP:"${CERT_IP}",DNS:"${CERT_HOSTNAME}.${DOMAIN_NAME}" build-client-full "${CLIENT_CERT_FILENAME}" nopass
    cp -p pki/ca.crt "${CLIENT_DIR}/ca.crt"
    cp -p pki/private/ca.key "${CLIENT_DIR}/ca.key"
    cp -p pki/issued/${CLIENT_CERT_FILENAME}.crt "${CLIENT_DIR}/client.crt"
    cp -p pki/private/${CLIENT_CERT_FILENAME}.key "${CLIENT_DIR}/client.key"
  fi
}

secure_docker_network_daemon() {
  # Bring down Docker to re-configure Docker to use flannel
  systemctl stop docker.service

  # Enable docker to listen on TLS enabled TCP port 
  sed -i "s|DOCKER_OPTS=\"-H unix:///var/run/docker.sock --insecure-registry gcr.io --insecure-registry ${DOCKER_REGISTRY_IP}:${DOCKER_REGISTRY_HOST_PORT}\"|DOCKER_OPTS=\"-H unix:///var/run/docker.sock --insecure-registry gcr.io --insecure-registry ${DOCKER_REGISTRY_IP}:${DOCKER_REGISTRY_HOST_PORT} --tlsverify --tlscacert=${STANDALONE_DOCKER_CERTS_DIR}/server/ca.crt --tlscert=${STANDALONE_DOCKER_CERTS_DIR}/server/server.crt --tlskey=${STANDALONE_DOCKER_CERTS_DIR}/server/server.key -H=${NODE_IP}:2376\"|g" /etc/sysconfig/docker
 
  # Start docker service 
  systemctl daemon-reload
  systemctl start docker.service

  # list docker service status
  systemctl status docker.service
}

usage() {
  echo -e "${COL_GREEN}Please specify what would you like to do, possible choices include:${COL_RESET}"
  echo ""
  echo -e "${COL_YELLOW}$0 master${COL_RESET}         ${COL_GREEN}(install docker & kubernetes master node.)${COL_RESET}"
  echo -e "${COL_YELLOW}$0 salve <1|2|..>${COL_RESET} ${COL_GREEN}(install docker & kubernetes slave node(s).)${COL_RESET}"
  echo -e "${COL_YELLOW}$0 docker <1|..>${COL_RESET}  ${COL_GREEN}(install standalone docker instance(s).)${COL_RESET}"
  echo -e "${COL_YELLOW}$0 registry${COL_RESET}       ${COL_GREEN}(install private docker registry.)${COL_RESET}"
  echo -e "${COL_YELLOW}$0 clean${COL_RESET}          ${COL_GREEN}(undo all changes to base OS.)${COL_RESET}"
  echo ""
  echo -e "${COL_RED}=====================================================================${COL_RESET}"
  echo -e "${COL_RED}NOTE:${COL_RESET}"
  echo -e "${COL_RED}=====================================================================${COL_RESET}"
  echo -e "${COL_GREEN}This script has been hardcoded to create no more than 2 kubernetes${COL_RESET}"
  echo -e "${COL_GREEN}slave nodes,to create more you will need to define them first.${COL_RESET}"
  echo -e "${COL_GREEN}Addtionally you can stand up 1 kubernetes master nodes and 1 ${COL_RESET}"
  echo -e "${COL_GREEN}private docker registry and 1 standalone docker instance.${COL_RESET}"
  echo ""
  exit 1 
}

##########################################################
# BEGIN MAIN SCRIPT
##########################################################

if [ $# > 0 ]; then
  
  if [ "$1" == "slave" ]; then
    export INSTALLER_TYPE='slave'
  elif [ "$1" == "master" ]; then
    export INSTALLER_TYPE='master'
  elif [ "$1" == "registry" ]; then
    export INSTALLER_TYPE='registry'
  elif [ "$1" == "docker" ]; then
    export INSTALLER_TYPE='docker'
  elif [ "$1" == "clean" ]; then
    export INSTALLER_TYPE='clean'
  else
    usage
  fi

  if [ "$INSTALLER_TYPE" == "slave" ] && [ $# != 2 ]; then
    echo -e "${COL_RED}ERROR!, You must provide the node index for slaves${COL_RESET}"
    exit 1
  else
    export NODE_INDEX=$2
  fi

  if [ "$INSTALLER_TYPE" == "docker" ] && [ $# != 2 ]; then
    echo -e "${COL_RED}ERROR!, You must provide the instance index to stand up standalone docker instance${COL_RESET}"
    exit 1
  else
    export NODE_INDEX=$2
  fi

else
  usage
fi

if [ "$INSTALLER_TYPE" == "master" ]; then
  NODE_IP=${MASTER_IP}
  NODE_NAME=${MASTER_NAME}
  NODE_NETMASK=${MASTER_NETMASK}
elif [ "$INSTALLER_TYPE" == "slave" ]; then
  NODE_IP=${MINION_IPS[($NODE_INDEX-1)]}
  NODE_NAME=${MINION_NAMES[($NODE_INDEX-1)]}
  NODE_NETMASK=${MINION_NETMASK[($NODE_INDEX-1)]}
elif [ "$INSTALLER_TYPE" == "registry" ]; then
  NODE_IP=${DOCKER_REGISTRY_IP}
  NODE_NAME=${DOCKER_REGISTRY_NAME}
  NODE_NETMASK=${DOCKER_REGISTRY_NETMASK}
  
  # make sure that we are not installing on master or slave nodes
  index=0
  for ip in $(/sbin/ifconfig | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p'); do
    let "index += 1"
    # master node
    if [ "$ip" == "$MASTER_IP" ]; then
      echo -e "${COL_RED}WARNING!, Can't install docker registry on kubernetes master node${COL_RESET}"
      exit 1
    fi
    # slave nodes
    for (( i=0; i<${#MINION_NAMES[@]}; i++)); do
      if [ "$ip" == "${MINION_IPS[$i]}" ]; then
        echo -e "${COL_RED}Can't install docker registry on kubernetes master node${COL_RESET}"
        exit 1
      fi
    done
  done
elif [ "$INSTALLER_TYPE" == "docker" ]; then
  NODE_IP=${STANDALONE_DOCKER_IPS[($NODE_INDEX-1)]}
  NODE_NAME=${STANDALONE_DOCKER_NAMES[($NODE_INDEX-1)]}
  NODE_NETMASK=${STANDALONE_DOCKER_NETMASK[($NODE_INDEX-1)]}
elif [ "$INSTALLER_TYPE" == "clean" ]; then
  if [ "no" == $(ask_yes_or_no "Are you sure, you want undo all your changes? [y/N]") ]; then
    echo -e "${COL_GREEN}Skipped... You saved me :-)${COL_RESET}"
    exit 0
  else
    echo -e "${COL_GREEN}Cleaning the previous install....${COL_RESET}"
    reset_os
    exit 0
  fi
fi

if [ "$INSTALLER_TYPE" != "clean" ]; then
  
  setup_proxy

  if [ "$setup_network" == true ]; then
    echo ""
    echo -e "${COL_MAGENTA}Pre-flight check 1:${COL_BLUE} Configure network....${COL_RESET}"
    echo ""

    if [ ! "$(cat /etc/sysconfig/network/ifcfg-eth0 | grep ${NODE_IP})" ]; then
      setup_network
      /sbin/reboot
    fi

    update_nameservers
  fi
fi

if [ "$INSTALLER_TYPE" != "clean" ]; then
  echo ""
  echo -e "${COL_MAGENTA}Pre-flight check 2:${COL_BLUE} Install zypper repos....${COL_RESET}"
  echo ""
  setup_repos

  echo ""
  echo -e "${COL_MAGENTA}Pre-flight check 3:${COL_BLUE} Install docker....${COL_RESET}"
  echo ""
  if ! which docker >/dev/null 2>&1; then
    install_docker
  fi
fi

if [ "$INSTALLER_TYPE" == "master" ]; then
  echo ""
  echo -e "${COL_MAGENTA}Step 1 of 8:${COL_BLUE} Setup bootstrap docker....${COL_RESET}"
  echo ""
  setup_docker_bootstrap

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 2 of 8:${COL_BLUE} Start etcd container....${COL_REST}"
  echo ""
  start_etcd

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 3 of 8:${COL_BLUE} Start flannel container....${COL_REST}"
  echo ""
  setup_flannel 'master'

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 4 of 8:${COL_BLUE} Start kerbernetes master container....${COL_REST}"
  echo ""
  start_kerbernetes_master

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 5 of 8:${COL_BLUE} Start kerbernetes master service proxy container....${COL_REST}"
  echo ""
  start_master_service_proxy

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5  
  echo ""
  echo -e "${COL_MAGENTA}Step 6 of 8:${COL_BLUE} Setup kubectl utility....${COL_REST}"
  echo ""
  install_kubectl

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5  
  echo ""
  echo -e "${COL_MAGENTA}Step 7 of 8:${COL_BLUE} Add cluster nodes....${COL_REST}"
  echo ""
  add_nodes_cluster

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 8 of 8:${COL_BLUE} Registering nodes....${COL_REST}"
  register_nodes

  echo ""
  echo -e "${COL_GREEN}Kerbernetes cluster is ready for use!${COL_REST}"
  echo ""
  kubectl get minions
elif [ "$INSTALLER_TYPE" == "slave" ]; then 
  echo ""
  echo -e "${COL_MAGENTA}Step 1 of 5:${COL_BLUE} Setup bootstrap docker.....${COL_REST}"
  echo ""
  setup_docker_bootstrap

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 2 of 5:${COL_BLUE} Start flannel container....${COL_REST}"
  echo ""
  setup_flannel 'slave'

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 3 of 5:${COL_BLUE} Start kubelet container....${COL_REST}"
  echo ""
  start_kubelet

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5
  echo ""
  echo -e "${COL_MAGENTA}Step 4 of 5:${COL_BLUE} Start kerbernetes slave service proxy container....${COL_REST}"
  echo ""
  start_slave_service_proxy

  # TODO:(SPURANAM) this is ugly do something here
  sleep 5  
  echo ""
  echo -e "${COL_MAGENTA}Step 5 of 5:${COL_BLUE} Setup kubectl utility....${COL_REST}"
  echo ""
  install_kubectl

  echo ""
  echo -e "${COL_GREEN}Kerbernetes salve is ready for use!${COL_REST}"
  echo ""
elif [ "$INSTALLER_TYPE" == "registry" ]; then 
  echo ""
  echo -e "${COL_MAGENTA}Step 1 of 4:${COL_BLUE} download docker registry source....${COL_REST}"
  echo ""
  get_docker_registry_source

  echo ""
  echo -e "${COL_MAGENTA}Step 2 of 4:${COL_BLUE} generate ssl certificates....${COL_REST}"
  echo ""
  gen_ssl_certs 'serveronly' "${DOCKER_REGISTRY_INSTALL_DIR}/certs" ${NODE_IP} ${NODE_NAME}

  echo ""
  echo -e "${COL_MAGENTA}Step 3 of 4:${COL_BLUE} build docker registry from source....${COL_REST}"
  echo "" 
  build_docker_registry

  echo ""
  echo -e "${COL_MAGENTA}Step 4 of 4:${COL_BLUE} start docker registry....${COL_REST}"
  echo ""
  start_docker_registry
  
  # tag secure registry image
  docker tag secure_registry:latest ${DOCKER_REGISTRY_IP}:${DOCKER_REGISTRY_HOST_PORT}/secure_registry:latest

  echo ""
  echo -e "${COL_GREEN}Docker registry is ready for use!${COL_REST}"
  echo ""
elif [ "$INSTALLER_TYPE" == "docker" ]; then
  echo ""
  echo -e "${COL_MAGENTA}Step 1 of 2:${COL_BLUE} generate client and server ssl certificates....${COL_REST}"
  echo ""
  gen_ssl_certs 'clientserver' "${STANDALONE_DOCKER_CERTS_DIR}" ${NODE_IP} ${NODE_NAME}

  echo ""
  echo -e "${COL_MAGENTA}Step 2 of 2:${COL_BLUE} re-configure docker daemon to listen on TLS enable TCP port${COL_REST}"
  echo ""
  secure_docker_network_daemon

  echo ""
  echo -e "${COL_GREEN}Docker daemon is ready for use!${COL_REST}"
  echo ""
fi
