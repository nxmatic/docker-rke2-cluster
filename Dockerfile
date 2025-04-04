FROM debian:bookworm-slim AS assets

VOLUME [ "/run/secrets" ]

SHELL [ "/usr/bin/env", "-S", "bash", "-ex", "-o", "pipefail", "-c" ]

ENV DEBIAN_FRONTEND=noninteractive

VOLUME [ "/assets" ]

RUN <<EoR
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
  mkdir -p /binaries
  mkdir -p /dpkgs
  mkdir -p /rancher
EoR

RUN --mount=type=secret,id=gh-token,required=true <<EoR
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
    tar --extract --gunzip --directory=/binaries --file=/dev/stdin lazygit
EoR

RUN --mount=type=secret,id=gh-token,required=true <<EoR
  : Load GitHub token
  export GH_TOKEN=$(< /run/secrets/gh-token )

  : Get latest release of sysbox
  JSON=$( gh api 'repos/nestybox/sysbox/releases/latest' )
  TAG=$( jq -r .tag_name <<< "${JSON}" )
  VERSION=${TAG#v}
  ARCH=$( dpkg --print-architecture )
  DEB_URL=https://downloads.nestybox.com/sysbox/releases/${TAG}/sysbox-ce_${VERSION}-0.linux_${ARCH}.deb
  
  : Download sysbox deb package
  wget --content-disposition -P /dpkgs "$DEB_URL"
EoR

RUN --mount=type=secret,id=gh-token,required=true <<EoR
  : Load GitHub token
  export GH_TOKEN=$(< /run/secrets/gh-token )
  
  : Get the latest release of cilium
  JSON=$( gh api 'repos/cilium/cilium-cli/releases/latest' )
  TAG=$( jq -r .tag_name <<< "${JSON}" )
  VERSION=${TAG#v}
  ARCH=$( dpkg --print-architecture ) 
  DOWNLOAD_URL=$( jq -r ".assets[] | select( .name == \"cilium-linux-${ARCH}.tar.gz\" ) | .browser_download_url" <<< "${JSON}" )
  : Download cilium cli
  mkdir -p /rancher/usr/local/bin
  curl -L --fail $DOWNLOAD_URL |
    tar xzvfC - /rancher/usr/local/bin
EoR

COPY <<EoF /rancher/etc/rancher/rke2/bashrc
set -a
PATH=/var/lib/rancher/rke2/bin:$PATH
KUBECONFIG=/etc/rancher/rke2/rke2.yaml
CONTAINERD_ADDRESS=/run/k3s/containerd/containerd.sock
CONTAINERD_NAMESPACE=k8s.io
CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml
set +a
EoF

COPY <<EoF /rancher/etc/rancher/rke2/config.yaml
tls-san:
  - master-control-node
  - peer-control-node1
  - peer-control-node2
write-kubeconfig-mode: "0640"
etcd-expose-metrics: true
cni:
  - cilium
ingress-controller: traefik
debug: false
EoF

COPY --chmod=a+x <<EoF /rancher/usr/local/sbin/cilium-remount-shared.sh
#!/usr/bin/env -S bash -exu -o pipefail
: Remount cilium shared volumes

mount --make-shared -t bpf bpf /sys/fs/bpf
mount --make-shared /run
EoF

COPY <<EoF /rancher/etc/systemd/system/cilium-remount-shared.service
[Unit]
Description=Remount cilium required volumes as shared
Before=rke2-server.service
DefaultDependencies=no

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cilium-remount-shared.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EoF

COPY <<EoF /rancher/etc/systemd/system/rke2-install.service
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

COPY <<EoF /rancher/etc/systemd/system/rke2-server.service.d/post-start.conf
[Unit]
Requires=cilium-remount-shared.service
Wants=cilium-remount-shared.service
After=cilium-remount-shared.service

[Service]
ExecStartPost=/usr/local/sbin/rke2-post-start.sh
EoF

COPY <<EoF /rancher/etc/systemd/system/rke2-agent.service.d/post-start.conf
[Service]
ExecStartPost=/usr/local/sbin/rke2-post-start.sh
EoF

COPY --chmod=a+x <<EoF /rancher/usr/local/sbin/rke2-post-start.sh 
#!/usr/bin/env -S bash -exu -o pipefail
: Load the RKE2 bashrc system wide
source <( cat <<'EoRC' | tee -a /etc/bash.bashrc
: RKE2 server environment variables
source /etc/rancher/rke2/bashrc
EoRC
)
: Set kube-system as the default namespace
kubectl config set-context --current --namespace kube-system
EoF

COPY <<EoF /rancher/var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml
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

FROM jrei/systemd-debian:12 AS systemd

ENV DEBIAN_FRONTEND=noninteractive
SHELL [ "/usr/bin/env", "-S", "bash", "-ex", "-o", "pipefail", "-c" ]

EXPOSE 22

RUN <<EoR
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

RUN <<EoR
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
    apt-transport-https \
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

RUN <<EoR
  : Install apt files database
  apt-get install -y apt-file 
  apt-file update
EoR

RUN <<EoR
  : Install man pages
  apt-get install -y man
  mandb
EoR

RUN <<EoR
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

FROM systemd AS router

RUN <<EoR
  : Install required packages
  apt-get install --no-install-recommends -y \
    bridge-utils \
    iproute2 \
    dnsutils
  
    : Enable IP forwarding
    cat <<EoF | cut -c 3- | tee -a /etc/sysctl.d/10-ipforward.conf
    net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.forwarding=1
  EoF
  
    : Add iptables rules for forwarding traffic between networks
    : iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
    : iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
    : iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
    : iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  
    : Save iptables rules
    : iptables-save > /etc/iptables/rules.v4
EoR

FROM systemd AS control-node

RUN <<EoR
  : Install helm command line tool
  curl https://baltocdn.com/helm/signing.asc | gpg --dearmor | sudo tee /usr/share/keyrings/helm.gpg > /dev/null
  cat <<EoF | cut -c 3- | tee /etc/apt/sources.list.d/helm-stable-debian.list
  deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/helm.gpg] https://baltocdn.com/helm/stable/debian/ all main
EoF
  apt-get update
  apt-get install --no-install-recommends -y \
    helm
EoR

RUN --mount=type=bind,from=assets,source=/,target=/.assets <<EoR
  : Install sysbox
  apt-get install --no-install-recommends -y \
    /.assets/dpkgs/sysbox-ce*.deb || 
    ( echo "Sysbox installation failed"; exit 0 )
EoR

RUN --mount=type=bind,from=assets,source=/,target=/.assets <<EoR
  : Install lazygit
  install -m 755 /.assets/binaries/lazygit /usr/local/bin/lazygit
EoR

RUN --mount=type=bind,from=assets,source=/,target=/.assets <<EoR
  : Install Rancher configuration assets
  rsync -av /.assets/rancher/ /
EoR

FROM control-node AS master-control-node

RUN <<EoR
  : Install RKE2 server

  : RKE2 control 1 install script
  cat <<EoF | cut -c 3- | tee -a /usr/local/sbin/rke2-install.sh
  #!/usr/bin/env -S bash -exu -o pipefail

  : Install the RKE2 server binaries
  curl -sfL https://get.rke2.io | 
    env DEBUG=1 INSTALL_RKE2_TYPE=server sh -
 
  : Enable and start the RKE2 server service
  systemctl enable cilium-remount-shared
  systemctl enable rke2-server
  systemctl start rke2-server
EoF
  chmod +x /usr/local/sbin/rke2-install.sh
  
  : Append RKE2 control 1 VIP deployment script
  cat <<EoF | cut -c 3- | tee -a /usr/local/sbin/rke2-post-start.sh
  : Install kube-vip on first control
  : kubectl apply -f https://kube-vip.io/manifests/rbac.yaml

  : Load kube-vip image
  : ctr images pull ghcr.io/kube-vip/kube-vip:latest

  : Generate kube-vip daemonset manifest
  : ctr -n k8s.io run --rm --net-host ghcr.io/kube-vip/kube-vip:latest               \
    vip /kube-vip manifest daemonset                                               \
      --arp --interface eth0 --address master-control-node --controlplane  --leaderElection \
      --taint --services --inCluster | 
      tee /var/lib/rancher/rke2/server/manifests/kube-vip.yaml
EoF

  : Enable the RKE2 install script
  systemctl enable rke2-install
EoR

FROM control-node AS peer-control-node

RUN <<EoR
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

