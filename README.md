# cilium
The CRDs relative to cilium are well described on [docs.crds.dev][1]

[1]: https://doc.crds.dev/github.com/cilium/cilium@1.17.1

# installing

```
 # docker buildx build --build-arg=CLUSTER_NAME=bioskop --build-arg=CLUSTER_ID=1 --build-context=dpkgs.d=dpkgs.d/ --secret=id=gh-token,env=GH_TOKEN --secret=id=tsid,env=TSID --secret=id=tskey,env=TSKEY --target assets --load --tag rke2-assets .
 # docker compose down --remove-orphans -v && docker-compose --env-file .env.bioskop up --build -d master-control-node
```