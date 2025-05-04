# docker-language-server: ignore

FROM scratch AS dpkgs
COPY --from=dpkgs.d . /

FROM debian:bookworm-slim AS assets

ARG CLUSTER_NAME=default
ARG CLUSTER_ID=1

ENV DEBIAN_FRONTEND=noninteractive
SHELL [ "/usr/bin/env", "-S", "bash", "-ex", "-o", "pipefail", "-c" ]

VOLUME [ "/run/secrets" ]
VOLUME [ "/assets" ]

RUN <<'EoR'
  : Upgrade system
  apt-get update

  : Install required packages
  apt-get install --no-install-recommends -y \
    binutils \
    curl wget \
    git gh jq \
    tar gzip bzip2 xz-utils \
    ca-certificates

  : Create assets directory
  mkdir -p /assets/binaries
  mkdir -p /assets/dpkgs
  mkdir -p /assets/rancher
  mkdir -p /assets/bird
EoR

# Download the binaries 

RUN --mount=type=secret,id=gh-token,required=true <<'EoR'
  : Load GitHub token
  export GH_TOKEN=$(< /run/secrets/gh-token )

  : Get latest release of lazygit
  JSON=$( gh api 'repos/jesseduffield/lazygit/releases/latest' )
  TAG=$( jq -r .tag_name <<< "${JSON}" )
  VERSION=${TAG#v}
  ASSETS_URL=$( jq -r .assets_url <<< "${JSON}" )
  TARBALL_URL=$( curl -sL $ASSETS_URL | 
    jq -r ".[] | select( .name == \"lazygit_${VERSION}_Linux_arm64.tar.gz\" ) | .browser_download_url" )
  
  : Download and extract lazygit
  curl -sL -o /dev/stdout "${TARBALL_URL}" |
    tar --extract --gunzip --directory=/assets/binaries --file=/dev/stdin lazygit
EoR

RUN --mount=type=secret,id=gh-token,required=true \
    --mount=from=dpkgs,target=/dpkgs.d <<'EoR'
  : Get latest release of sysbox
  
  : Load GitHub token
  export GH_TOKEN=$(< /run/secrets/gh-token )

  : Get the download debian package URL from github
  JSON=$( gh api 'repos/nestybox/sysbox/releases/latest' )
  TAG=$( jq -r .tag_name <<< "${JSON}" )
  VERSION=${TAG#v}
  ARCH=$( dpkg --print-architecture )
  DEB_FILE=sysbox-ce_${VERSION}-0.linux_${ARCH}.deb
  DEB_URL=https://downloads.nestybox.com/sysbox/releases/${TAG}/${DEB_FILE}
  
  : Download the debian package
  wget --quiet --content-disposition -P /assets/dpkgs "$DEB_URL" ||
    cp /dpkgs.d/${DEB_FILE} /assets/dpkgs/
EoR

RUN --mount=type=secret,id=gh-token,required=true <<'EoR'
  : Get latest release of lazygit

  : Load GitHub token
  export GH_TOKEN=$(< /run/secrets/gh-token )

  : Get the download tarball URL from github
  JSON=$( gh api 'repos/jesseduffield/lazygit/releases/latest' )
  TAG=$( jq -r .tag_name <<< "${JSON}" )
  VERSION=${TAG#v}
  ASSETS_URL=$( jq -r .assets_url <<< "${JSON}" )
  TARBALL_URL=$( curl -sL $ASSETS_URL | 
    jq -r ".[] | select( .name == \"lazygit_${VERSION}_Linux_arm64.tar.gz\" ) | .browser_download_url" )
  
  : Download and extract the binaries
  curl -sL -o /dev/stdout "${TARBALL_URL}" |
    tar --extract --gunzip --directory=/assets/binaries --file=/dev/stdin lazygit
EoR

RUN --mount=type=secret,id=gh-token,required=true <<'EoR'
  : Get the latest release of yq-go

  : Load GitHub token
  export GH_TOKEN=$(< /run/secrets/gh-token )
  
  : Get the download tarball URL from github
  JSON=$( gh api 'repos/mikefarah/yq/releases/latest' )
  TAG=$( jq -r .tag_name <<< "${JSON}" )
  VERSION=${TAG#v}
  ARCH=$( dpkg --print-architecture ) 
  DOWNLOAD_URL=$( jq -r ".assets[] | select( .name == \"yq_linux_${ARCH}\" ) | .browser_download_url" <<< "${JSON}" )
  
  : Download and extract the binaries
  curl -sL --fail -o /assets/binaries/yq $DOWNLOAD_URL
  chmod +x /assets/binaries/yq
EoR

RUN --mount=type=secret,id=gh-token,required=true <<'EoR'
  : Get the latest release of cilium

  : Load GitHub token
  export GH_TOKEN=$(< /run/secrets/gh-token )
  
  : Get the download tarball URL from github
  JSON=$( gh api 'repos/cilium/cilium-cli/releases/latest' )
  TAG=$( jq -r .tag_name <<< "${JSON}" )
  VERSION=${TAG#v}
  ARCH=$( dpkg --print-architecture ) 
  DOWNLOAD_URL=$( jq -r ".assets[] | select( .name == \"cilium-linux-${ARCH}.tar.gz\" ) | .browser_download_url" <<< "${JSON}" )
  
  : Download and extract the binaries
  mkdir -p /assets/rancher/usr/local/bin
  curl -sL --fail $DOWNLOAD_URL |
    tar --extract --gunzip --directory=/assets/rancher/usr/local/bin --file=/dev/stdin
EoR

# Define the bird configuration files

COPY <<'EoF' /assets/bird/etc/systemd/system/bird.service.d/override.conf
[Service]
ExecStartPre=
ExecStartPre=/usr/lib/bird/prepare-environment
ExecStartPre=/usr/lib/bird/cluster-pre-start.sh
ExecStartPre=/usr/sbin/bird -p
EoF

COPY --chmod=a+x <<'EoF' /assets/bird/usr/lib/bird/cluster-pre-start.sh
#!/usr/bin/env -S bash -exu -o pipefail

: Load the cluster environment variables
source <( cat /proc/1/environ | tr '\0' '\n' | grep -E '^(CLUSTER_)' )

: Generate the cluster configuration file
cat <<EoConf | tee /etc/bird/cluster.conf
define MASTER_CONTROL_NODE_IP=172.31.$CLUSTER_ID.2;
define PEER1_CONTROL_NODE_IP=172.31.$CLUSTER_ID.3;
define PEER2_CONTROL_NODE_IP=172.31.$CLUSTER_ID.4;
define PEER3_CONTROL_NODE_IP=172.31.$CLUSTER_ID.5;
EoConf
EoF

COPY <<'EoF' /assets/bird/etc/bird/bird.conf
# This is the main BIRD configuration file.
# It is used to configure the BIRD routing daemon.
# See the BIRD documentation for more information.
# https://bird.network.cz/?get_doc&f=bird-2.html


log syslog all;
router id from "eth0";
include "cluster.conf";
include "protocols.d/*.conf";
EoF

COPY <<'EoF' /assets/bird/etc/bird/envvars
# This is the main BIRD environment variables file.
BIRD_RUN_USER=bird
BIRD_RUN_GROUP=bird
#BIRD_ARGS=
EoF

COPY <<'EoF' /assets/bird/etc/bird/protocols.d/device.conf
# This is the BIRD device protocol configuration file.
protocol device {
  interface "eth0";
  interface "eth1";
}
EoF

COPY <<'EoF' /assets/bird/etc/bird/protocols.d/direct.conf
# This is the BIRD direct protocol configuration file.
protocol direct {
  ipv4;
  interface "eth*";
}
EoF

COPY <<'EoF' /assets/bird/etc/bird/protocols.d/kernel.conf
# This is the BIRD kernel protocol configuration file.
protocol kernel kernel4 {
  ipv4 {
    import none;
    export all;
  };
  learn;
}
EoF

COPY <<'EoF' /assets/bird/etc/bird/protocols.d/bgp.conf
# This is the BIRD BGP protocol configuration file.

template bgp node {
  local as 65000;
  passive off;
  ipv4 {
    import none;
    export where proto = "direct";
    next hop self;  # Critical for container networking
  };
}

protocol bgp master from node {
  neighbor MASTER_CONTROL_NODE_IP as 65000;
}

protocol bgp peer1 from node {
  neighbor PEER1_CONTROL_NODE_IP as 65000;
}

protocol bgp peer2 from node {
  neighbor PEER2_CONTROL_NODE_IP as 65000;
}

protocol bgp peer3 from node {
  neighbor PEER3_CONTROL_NODE_IP as 65000;
}
EoF

# Define the RKE2 configuration files
COPY <<'EoF' /assets/rancher/etc/rancher/rke2/bashrc
set -a
PATH=/var/lib/rancher/rke2/bin:$PATH
KUBECONFIG=/etc/rancher/rke2/rke2.yaml
CONTAINERD_ADDRESS=/run/k3s/containerd/containerd.sock
CONTAINERD_NAMESPACE=k8s.io
CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml

: load the container environment variables
source <( cat /proc/1/environ | tr '\0' '\n' | grep -E '^(CLUSTER_)' )
set +a
EoF

COPY <<'EoF' /assets/rancher/etc/rancher/rke2/config.yaml
tls-san:
  - localhost
  - master-control-node
  - peer-control-node1
  - peer-control-node2
write-kubeconfig-mode: "0640"
etcd-expose-metrics: true
cni:
  - cilium
ingress-controller: traefik
debug: false
cluster-cidr: 10.${CLUSTER_ID}.0.0/17
service-cidr: 10.${CLUSTER_ID}.128.0/17
EoF

COPY <<'EoF' /assets/rancher/var/lib/rancher/rke2/server/manifests/rke2-cilium-config.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: kube-system
---
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-cilium
  namespace: kube-system
spec:
  valuesContent: |-
    bgpControlPlane:
      enabled: true
    cluster:
      name: "default"
      id: 1
    clustermesh:
      useAPIServer: true
      apiserver:
        service:
          type: LoadBalancer
          loadBalancerClass: io.cilium/bgp-control-plane
    envoy:
      enabled: true
    hubble:
      enabled: true
      relay:
        enabled: true
      ui:
        enabled: true
    kubeProxyReplacement: true
    socketLB:
      hostNamespaceOnly: true
    operator:
      replicas: 1
      hostNetwork: true
---
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: rke2-ingress-nginx
  namespace: kube-system
spec:
  valuesContent: |-
    controller:
      metrics:
        service:
          annotations:
            prometheus.io/scrape: "true"
            prometheus.io/port: "10254"
      config:
        use-forwarded-headers: "true"
      allowSnippetAnnotations: "true"  
---
  apiVersion: "cilium.io/v2alpha1"
  kind: CiliumLoadBalancerIPPool
  metadata:
    name: "pool"
  spec:
    blocks:
      -  cidr: "172.31.255.128/25"
---
apiVersion: "cilium.io/v2alpha1"
kind: CiliumL2AnnouncementPolicy
metadata:
  name: l2policy
spec:
  loadBalancerIPs: true
  interfaces:
    - eth0
---
apiVersion: "cilium.io/v2alpha1"
kind: CiliumBGPClusterConfig
metadata:
  name: cilium-bgp
spec:
  bgpInstances:
    - name: "instance-65000"
      localASN: 65000
      peers:
        - name: "master"
          peerASN: 65000
          peerAddress: "master-control-node"
          peerConfigRef:
            name: "peer-config-generic"
        - name: "peer1"
          peerASN: 65000
          peerAddress: "peer1-control-node"
          peerConfigRef:
            name: "peer-config-generic"
        - name: "peer2"
          peerASN: 65000
          peerAddress: "peer2-control-node"
          peerConfigRef:
            name: "peer-config-generic"
        - name: "peer3"
          peerASN: 65000
          peerAddress: "peer3-control-node"
          peerConfigRef:
            name: "peer-config-generic"
---
apiVersion: cilium.io/v2alpha1
kind: CiliumBGPNodeConfigOverride
metadata:
  name: bgpv2-cplane-dev-multi-homing-worker
spec:
  bgpInstances:
    - name: "instance-65000"
      localPort: 179
---
apiVersion: "cilium.io/v2alpha1"
kind: CiliumBGPPeerConfig
metadata:
  name: peer-config-generic
spec:
  families:
    - afi: ipv4
      safi: unicast
      advertisements:
        matchLabels:
          advertise: "generic"
---
apiVersion: "cilium.io/v2alpha1"
kind: CiliumBGPAdvertisement
metadata:
  name: services
  labels:
    advertise: generic
spec:
  advertisements:
    - advertisementType: "PodCIDR"
    - advertisementType: "Service"
      service:
        addresses:
          - LoadBalancerIP
      selector: # select all services
        matchExpressions:
          - key: "somekey"
            operator: In
            values:
              - "never-used-value"
EoF

RUN --mount=type=secret,id=tskey,required=true \
    --mount=type=secret,id=tsid,required=true \
cat <<EoF > /assets/rancher/var/lib/rancher/rke2/server/manifests/rke2-tailscale.yaml
apiVersion: helm.cattle.io/v1
kind: HelmChart
metadata:
  namespace: kube-system
  name: rke2-tailscale-operator
spec:
  repo: https://pkgs.tailscale.com/helmcharts
  chart: tailscale-operator
  version: 1.82.0
  targetNamespace: tailscale-system
  createNamespace: true
  valuesContent: |-
    oauth:
      clientId: "$( cat /run/secrets/tsid )"
      clientSecret: "$( cat /run/secrets/tskey )"
    operatorConfig:
      hostname: "${CLUSTER_NAME}-tailscale-operator"
---
apiVersion: tailscale.com/v1alpha1
kind: Connector
metadata:
  name: ts-controlplane-lb-routes
spec:
  hostname: ${CLUSTER_NAME}-controlplane-lb-routes  # Name visible in Tailscale admin
  subnetRouter:
    advertiseRoutes:
EoF

COPY --chmod=a+x <<'EoF' /assets/rancher/usr/local/sbin/rke2-remount-shared.sh
#!/usr/bin/env -S bash -exu -o pipefail
: Remount shared volumes

mount --make-shared /
mount --make-shared -t bpf bpf /sys/fs/bpf
mount --make-shared /run
EoF

COPY <<'EoF' /assets/rancher/etc/systemd/system/rke2-remount-shared.service
[Unit]
Description=Remount RKE2 required volumes as shared
Before=rke2-server.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/rke2-remount-shared.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EoF

COPY <<'EoF' /assets/rancher/etc/systemd/system/rke2-install.service
  [Unit]
  Description=Run RKE2 Installation Script
  After=network.target
  ConditionPathExists=/usr/local/sbin/rke2-install.sh
  
  [Install]
  WantedBy=multi-user.target
  RequiredBy=multi-user.target
  
  [Service]
  Type=oneshot
  ExecStart=/usr/bin/env -S bash -c 'rke2-install.sh && systemctl disable rke2-install.service'
  RemainAfterExit=true
EoF

COPY <<'EoF' /assets/rancher/etc/systemd/system/rke2-server.service.d/start.conf
[Unit]
Requires=rke2-remount-shared.service
Wants=rke2-remount-shared.service
After=rke2-remount-shared.service

[Service]
ExecStartPre=/usr/local/sbin/rke2-pre-start.sh
ExecStartPost=/usr/local/sbin/rke2-post-start.sh
EoF

COPY <<'EoF' /assets/rancher/etc/systemd/system/rke2-agent.service.d/start.conf
[Service]
ExecStartPre=/usr/local/sbin/rke2-pre-start.sh
ExecStartPost=/usr/local/sbin/rke2-post-start.sh
EoF

COPY --chmod=a+x <<'EoF' /assets/rancher/usr/local/sbin/rke2-pre-start.sh
#!/usr/bin/env -S bash -exu -o pipefail

: Load the RKE2 bashrc 
source /etc/rancher/rke2/bashrc

EoF

COPY --chmod=a+x <<'EoF' /assets/rancher/usr/local/sbin/rke2-post-start.sh 
#!/usr/bin/env -S bash -exu -o pipefail

: Load the RKE2 bashrc 
source /etc/rancher/rke2/bashrc

: Load the RKE2 bashrc system wide
source <( cat <<'EoRC' | tee -a /etc/bash.bashrc

: RKE2 server environment variables
source /etc/rancher/rke2/bashrc
EoRC
)

: Patch the cluster kube context for the IP address
source <( ip --json addr show eth0 | 
          yq -p json -o shell '.[0].addr_info.[] | select(.family == "inet") | { "inet": .local }' )

yq --inplace --from-file=<( cat <<EoE
.clusters[0].cluster.server = "https://${inet}:6443" |
.users[0].name = "${CLUSTER_NAME}"
EoE
) /etc/rancher/rke2/rke2.yaml 

kubectl config rename-context default ${CLUSTER_NAME}
kubectl config use-context ${CLUSTER_NAME}
kubectl config set-context --current --user=${CLUSTER_NAME} --namespace=kube-system

mkdir -p /.docker-compose/.kubeconfig.d
rsync -a /etc/rancher/rke2/rke2.yaml /.docker-compose.d/.kubeconfig.d/rke2-${CLUSTER_NAME}.yaml
EoF

COPY <<'EoF' /assets/rancher/var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml
---
  apiVersion: helm.cattle.io/v1
  kind: HelmChartConfig
  metadata:
    name: rke2-ingress-nginx
    namespace: kube-system
  spec:
    valuesContent: |-
      controller:
        metrics:
          service:
            annotations:
              prometheus.io/scrape: "true"
              prometheus.io/port: "10254"
        config:
          use-forwarded-headers: "true"
        allowSnippetAnnotations: "true"  
EoF

FROM jrei/systemd-debian:bookworm AS systemd

ENV DEBIAN_FRONTEND=noninteractive
ENV CLUSTER_NAME=default
ENV CLUSTER_ID=1

SHELL [ "/usr/bin/env", "-S", "bash", "-ex", "-o", "pipefail", "-c" ]

EXPOSE 22

RUN <<'EoR'
  : Add backports repository
  cat <<EoF | cut -c 3- | tee -a /etc/apt/sources.list.d/debian-backports.sources
  Types: deb
  # http://snapshot.debian.org/archive/debian/20250224T000000Z
  URIs: http://deb.debian.org/debian
  Suites: bookworm-backports
  Components: main
  Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EoF

  : Update package lists
  apt-get update
  apt-get dist-upgrade -y
EoR

RUN <<'EoR'
  : Install systemd dependencies
  apt-get install -y \
    kmod procps \
    systemd \
    systemd-sysv \
    systemd-container \
    systemd-timesyncd \
    systemd-resolved

  : Enable networking services
  systemctl enable systemd-networkd
  # systemctl enable systemd-networkd-wait-online
  systemctl enable systemd-resolved
EoR

RUN <<'EoR'
  : Install required packages
  apt-get install --no-install-recommends -y \
    uuid-runtime \
    apt-transport-https apt-utils \
    bash-completion vim emacs-nox less man jq bc \
    lsof tree psmisc htop lshw sysstat dstat \
    bridge-utils iproute2 iputils-ping iptables dnsutils traceroute \
    curl wget nmap socat netcat-openbsd rsync net-tools telnet \
    p7zip-full \
    git gh \
    gnupg \
    file binutils acl pv \
    strace tshark nmap \
    open-iscsi nfs-common \
    ca-certificates
EoR

RUN <<'EoR'
  : Install apt files database
  apt-get install -y apt-file 
  apt-file update
EoR

RUN <<'EoR'
  : Install man pages
  apt-get install -y man
  mandb
EoR

RUN <<'EoR'
  : Install ssh server
  apt-get install --no-install-recommends -y \
    openssh-server sudo
  
  : Enable sudo without password
  cat <<EoF | cut -c 3- | tee -a /etc/sudoers
  %sudo ALL=(ALL) NOPASSWD:ALL
EoF

  : Enable ssh password authentication [ todo: use patch instead ]
  cat <<EoF | cut -c 3- | tee -a /etc/ssh/sshd_config.d/permit-root-login.conf
  PermitRootLogin yes
EoF

  : Enable ssh authorized keys
  mkdir -p /etc/ssh/authorized_keys.d
  cat <<EoF | cut -c 3- | tee -a /etc/ssh/sshd_config.d/authorized_keys.conf
  AuthorizedKeysCommand /bin/cat /etc/ssh/authorized_keys.d/%u
  AuthorizedKeysCommandUser sshd
EoF

  : Disable host key checking
  cat <<EoF | cut -c 3- | tee -a /etc/ssh/ssh_config.d/disable-host-key-checking.conf
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
EoF

  : Generate the VIP host shared key and add it to the root authorized keys
  mkdir -p /etc/ssh/keys.d
  ssh-keygen -t ed25519 -N '' -f /etc/ssh/keys.d/vip
  cat /etc/ssh/keys.d/vip.pub | tee -a /etc/ssh/authorized_keys.d/root
  
  : Enable ssh
  systemctl enable ssh

  : Enable othe systemd services
  systemctl enable systemd-timesyncd
  systemctl enable systemd-logind
  systemctl enable systemd-journald

  : Disable mac address assignment
  cat <<'EoF' | cut -c 3- | tee -a /etc/systemd/network/10-veth.link
  [Match]
  Driver=veth
  [Link]
  MACAddressPolicy=none
EoF

  : Fixup systemd-networkd-wait-online using a dummy interface
  
  mkdir -p /etc/systemd/network
  cat <<'EoF' | cut -c 3- | tee -a /etc/systemd/network/00-dummy.netdev
  [NetDev]
  Name=dummy0
  Kind=dummy
EoF

  mkdir -p /etc/systemd/network
  cat <<'EoF' | cut -c 3- | tee -a /etc/systemd/network/00-dummy.network
  [Match]
  Name=dummy0

  [Link]
  RequiredForOnline=yes

  [Network]
  Address=127.255.255.1/31
EoF

  mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
  cat <<'EoF' | cut -c 3- | tee -a /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf
  [Service]
  ExecStart=
  ExecStart=/usr/bin/systemd-networkd-wait-online --interface=dummy0 --timeout=1
EoF

EoR

FROM systemd AS bird

COPY <<'EoF' /etc/apt/sources.list.d/debian-sid.sources
Types: deb
# http://snapshot.debian.org/archive/debian/20250224T000000Z
URIs: http://deb.debian.org/debian
Suites: sid
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EoF

COPY <<'EoF' /etc/apt/conf.d/default-release
APT::Default-Release "stable";
EoF

COPY <<'EoF' /etc/sysctl.d/10-ipforward.conf
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
EoF

RUN <<'EoR'
  : Update package lists
  apt-get update

  : Install required packages
  apt-get install --no-install-recommends -y \
    bridge-utils \
    iproute2 \
    dnsutils

  : Install bird3 from sid
  apt-get -y install -t sid \
    bird3

  : Enable the bird systemd service
  systemctl enable bird
EoR

COPY --from=assets /bird/ /

FROM systemd AS control-node

RUN <<'EoR'
  : Install helm command line tool
  curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
  cat <<EoF | cut -c 3- | tee /etc/apt/sources.list.d/helm-stable-debian.list
  deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main
EoF
  apt-get update
  apt-get install --no-install-recommends -y \
    helm
EoR

RUN --mount=type=bind,from=assets,source=/assets/dpkgs/,target=/.dpkgs <<'EoR'
  : Install debian packages
  apt-get install --no-install-recommends -y /.dpkgs/*.deb ||
    rsync -a /.dpkgs/ /var/dpkgs/
EoR

RUN --mount=type=bind,from=assets,source=/assets/,target=/.assets <<'EoR'
  : Install binaries
  source <( printf "%s\n" /.assets/binaries/* |
            xargs -I {} echo "install -m 755 {} /usr/local/bin/" )
EoR

RUN --mount=type=bind,from=assets,source=/assets/,target=/.assets <<'EoR'
  : Install Rancher configuration assets
  rsync -av /.assets/rancher/ /

  : Patch asset files with cluster environment variables
  cat <<'EoF' | cut -c 3- | tee -a /usr/local/sbin/rke2-pre-start.sh
  : Patch the cilium config with cluster environment variables
  yq --inplace --from-file=<( cat <<EoE | tee /tmp/kube-system.yq
  ( select( .kind == "CiliumBGPAdvertisement" ) | .spec ) |=
    ( .advertisements[0].advertisementType = "PodCIDR" ) |
  ( select( .kind == "CiliumBGPNodeConfigOverride" ) | .spec ) |=
    ( .bgpInstances[0].localPort = 179 ) |
  ( select( .kind == "CiliumBGPNodeConfigOverride" ) | .spec.bgpInstances[0].peers[] ) |=
    ( .peerAddress = "172.31.${CLUSTER_ID}.2" ) |
  ( select( .kind == "HelmChartConfig") | .spec ) |=
    ( .valuesContent |= ( from_yaml | 
                           .cluster.name = "${CLUSTER_NAME}" |
                           .cluster.id = ${CLUSTER_ID} |
                           to_yaml ) ) |
  ( select( .kind == "CiliumLoadBalancerIPPool" ) | .spec ) |=
    ( .blocks[0] = { "cidr": "172.31.${CLUSTER_ID}.128/25", "min": "129", "max": "254" } ) |
  ( select( .kind == "CiliumBGPClusterConfig" ) | .spec ) |=
    with( .bgpInstances[] | select( .name == "instance-65000" ); 
      with( .peers[] | select( .name == "master"); .peerAddress = "172.31.${CLUSTER_ID}.2" ) |
      with( .peers[] | select( .name == "peer1");  .peerAddress = "172.31.${CLUSTER_ID}.3" ) |
      with( .peers[] | select( .name == "peer2");  .peerAddress = "172.31.${CLUSTER_ID}.4" ) |
      with( .peers[] | select( .name == "peer3");  .peerAddress = "172.31.${CLUSTER_ID}.5" ) )
  EoE
  ) /var/lib/rancher/rke2/server/manifests/rke2-cilium-config.yaml

  yq --inplace --from-file=<( cat <<EoE
  ( select( .kind == "Connector" ) | .spec ) |=
    ( .subnetRouter.advertiseRoutes = 
      [ "172.31.${CLUSTER_ID}.0/28", "172.31.${CLUSTER_ID}.128/25" ] )
  EoE
  ) /var/lib/rancher/rke2/server/manifests/rke2-tailscale.yaml
  
  mkdir -p /etc/rancher/rke2/config.yaml.d
  touch /etc/rancher/rke2/config.yaml.d/cidr.yaml
  yq --inplace --from-file=<( cat <<EoF
  . += { "cluster-cidr": "10.${CLUSTER_ID}.0.0/17", "service-cidr": "10.${CLUSTER_ID}.128.0/17" }
  EoF
  ) /etc/rancher/rke2/config.yaml.d/cidr.yaml

EoF

EoR

FROM control-node AS master-control-node

RUN <<'EoR'
  : Install RKE2 server

  : RKE2 control 1 install script
  cat <<EoF | cut -c 3- | tee -a /usr/local/sbin/rke2-install.sh
  #!/usr/bin/env -S bash -exu -o pipefail

  : Install the RKE2 server binaries
  curl -sfL https://get.rke2.io | 
    env DEBUG=1 INSTALL_RKE2_TYPE=server sh -
 
  : Enable and start the RKE2 server service
  systemctl enable rke2-remount-shared
  systemctl enable rke2-server
  systemctl start rke2-server
EoF
  chmod +x /usr/local/sbin/rke2-install.sh
  
  : Enable the RKE2 install script
  systemctl enable rke2-install
EoR

COPY <<'EoF' /usr/local/sbin/rke2-vip-install.sh
  : Install kube-vip on master control node
  kubectl apply -f https://kube-vip.io/manifests/rbac.yaml

  : Load kube-vip image
  ctr images pull ghcr.io/kube-vip/kube-vip:latest

  : Generate kube-vip daemonset manifest
  ctr -n k8s.io run --rm --net-host ghcr.io/kube-vip/kube-vip:latest               \
    vip /kube-vip manifest daemonset                                               \
      --arp --interface eth0 --address master-control-node --controlplane  --leaderElection \
      --taint --services --inCluster | 
      tee /var/lib/rancher/rke2/server/manifests/kube-vip.yaml
EoF

FROM control-node AS peer-control-node

RUN <<'EoR'
  : RKE2 control 2 install script
  cat <<'EoF' | cut -c 3- | tee -a /usr/local/sbin/rke2-install.sh
  #!/usr/bin/env -S bash -exu -o pipefail

  : Install RKE2
  curl -sfL https://get.rke2.io | 
    env DEBUG=1 INSTALL_RKE2_TYPE=server sh -

  : Join the RKE2 cluster using the token
  mkdir -p /etc/rancher/rke2/config.yaml.d
  cat <<EoF | tee -a /etc/rancher/rke2/config.yaml.d/cluster-admission-token.yaml
  server: 'https://master-control-node:9345'
  token: '$( ssh -i /etc/ssh/keys.d/vip root@master-control-node cat /var/lib/rancher/rke2/server/token )'
  EoF

  systemctl enable rke2-server
  systemctl start rke2-server
EoF
  chmod +x /usr/local/sbin/rke2-install.sh

  : Enable the RKE2 install
  systemctl enable rke2-install.service
EoR

