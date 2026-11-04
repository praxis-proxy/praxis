# Praxis Kubernetes base

This is a provider-neutral, restricted-Pod-Security baseline for a two-replica
Praxis Deployment. It publishes only the data listener through a ClusterIP
Service. The admin API remains on the pod loopback; health and Prometheus
metrics use the pod interface on port `9902`.

## Apply

```console
kubectl kustomize deploy/kubernetes/base
kubectl apply -k deploy/kubernetes/base
```

The base uses the immutable `0.7.5` release image. Production overlays should
replace it with the approved release digest before applying. The ConfigMap name
is deliberately stable (`disableNameSuffixHash: true`): changing
`praxis.yaml` is handled by Praxis's reload watcher and does not create a
generated-name rollout. The source file is mounted as `config.yaml`.

The optional `praxis-tls` Secret is mounted as a directory at
`/etc/praxis/tls`; the base does not create a private key or enable TLS on the
listener. A TLS overlay must add the matching listener configuration and Secret.

## Operational assumptions

- Kubernetes supports `apps/v1`, `policy/v1`, and `networking.k8s.io/v1`.
- The cluster has a `monitoring` namespace whose Prometheus pods carry
  `app.kubernetes.io/name: prometheus`.
- The CNI enforces NetworkPolicy. If kubelet probes originate from node IPs
  that are subject to ingress policy, add the node CIDRs in an environment
  overlay; the base cannot infer provider-specific node ranges.
- Resource requests are a starting point and must be adjusted from measured
  traffic. The deployment intentionally has no CPU limit to avoid CFS
  throttling; memory is capped at 512 MiB.

The base excludes the optional Valkey evaluation component because that work
depends on #1299. Rollout/load acceptance remains owned by the separate #1302
workstream.

## Recovery

Keep the previous image digest and the prior ConfigMap contents. Use
`kubectl rollout undo deployment/praxis` for an image or pod-template rollback,
and restore the ConfigMap separately because Deployment rollback does not
restore externally mounted configuration. The PDB protects voluntary
evictions only; it cannot prevent loss from a failed node or force deletion.

