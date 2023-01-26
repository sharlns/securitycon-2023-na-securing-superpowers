# Securing the Superpowers - Who loaded that eBPF program?

This repository contains the demo and the corresponding instructions that was presented at SecurityCon 2023 NA, Seattle
during `Securing the Superpowers - Who loaded that eBPF program?`.

## Environment

Create a GKE cluster:
```bash
export NAME="$(whoami)-$RANDOM"
gcloud container clusters create "${NAME}" \
  --zone europe-central2-a \
  --num-nodes 1
```

Deploy Tetragon:
```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system
kubectl rollout status -n kube-system ds/tetragon -w
```

Apply a TracingPolicy which would detect BPF program loading and BPF map creation:
```bash
kubectl apply -f bpf.yaml
```

### Demo 1 - Who loaded that simple BPF program? And created the map?

Create `washington` namespace:

```bash
kubectl create ns washington
namespace/washington created
```

Apply `seattle-bpf-droid` pod on `washington` namespace:
```bash
kubectl apply -f seattle-bpf-droid.yaml -n washington
pod/seattle-bpf-droid created
```

Wait until the `seattle-bpf-droid` pod is ready:
```bash
kubectl get pods -n washington
NAME                READY   STATUS    RESTARTS   AGE
seattle-bpf-droid   1/1     Running   0          32s
```

The `seattle-bpf-droid` pod is doing 2 main instructions periodically, in every 30s:
1. Loading a BPF program
2. Creating a BPF map

#### Detecting BPF program loading

Start observing the logs from the `seattle-bpf-droid` pod:
```bash
kubectl exec -it -n kube-system tetragon-nljct -c tetragon -- /bin/bash
tetra getevents -o compact -pod seattle-bpf-droid
```

The pod is loading a `seattle_bpf_prog.o` BPF program with `kprobe` type in every 30s with `bpftool`,
which can be seen by the following events:
```bash
🚀 process washington/seattle-bpf-droid /usr/local/bin/bpftool prog load seattle_bpf_prog.o /sys/fs/bpf/a85d485007 --legacy type kprobe
🐝 bpf_check washington/seattle-bpf-droid /usr/local/bin/bpftool BPF_PROG_TYPE_SOCKET_FILTER  instruction count 2
🐝 bpf_check washington/seattle-bpf-droid /usr/local/bin/bpftool BPF_PROG_TYPE_SOCKET_FILTER test instruction count 2
🐝 bpf_check washington/seattle-bpf-droid /usr/local/bin/bpftool BPF_PROG_TYPE_KPROBE amazing_func instruction count 2
💥 exit    washington/seattle-bpf-droid /usr/bin/sleep 30s 0
```

To be able to detect BPF program loading, Tetragon hooks into the `bpf_check` function which represents the Verifier check during the program load. This is performed
everytime a BPF program is loaded. The `BPF_PROG_TYPE_KPROBE` represents the program type, the `amazing_func` represents the
function name and the `instruction count 2` tells how many instructions the specific program contain.

The program type can be also `BPF_PROG_TYPE_SOCKET_FILTER`, `BPF_PROG_TYPE_XDP` etc. We will see examples for those later.

#### Detecting BPF map creation

The pod is also creating a `tetragon_bpf_5016` BPF map and pin it to `/sys/fs/bpf/seattle_5016` location by using `bpftool`.
We can see that the map was hash map (`BPF_MAP_TYPE_HASH`), the key and the value size were `4` and the max entries were `4` as well.

```bash
🚀 process washington/seattle-bpf-droid /usr/local/bin/bpftool map create /sys/fs/bpf/seattle_5016 type hash key 4 value 20 entries 4 name tetragon_bpf_5016
🐝 bpf_check washington/seattle-bpf-droid /usr/local/bin/bpftool BPF_PROG_TYPE_SOCKET_FILTER  instruction count 2
🗺 bpf_map_alloc washington/seattle-bpf-droid /usr/local/bin/bpftool BPF_MAP_TYPE_HASH tetragon_bpf_50 key size 4 value size 20 max entries 4
💥 exit    washington/seattle-bpf-droid /usr/local/bin/bpftool map create /sys/fs/bpf/seattle_5016 type hash key 4 value 20 entries 4 name tetragon_bpf_5016 0
```

To be able to detect BPF map creation, Tetragon hooks into the `security_bpf_map_alloc` function which is called during a 
BPF map create. 

### Demo 2 - Which programs were loaded by Cilium?

As a second demo, we will show a real use case and detect what BPF programs were loaded by Cilium and what BPF maps were created.

Create `cilium` namespace:
```bash
kubectl create ns cilium
namespace/cilium created
```

Set the `NAME` and `ZONE` variables to your cluster:
```bash
NAME=<cluster_name>
ZONE=<zone_name>
```

Extract the cluster CIDR to enable native routing:
```bash
NATIVE_CIDR="$(gcloud container clusters describe "${NAME}" --zone "${ZONE}" --format 'value(clusterIpv4Cidr)')"
echo $NATIVE_CIDR
```

Install Cilium via helm:
```bash
helm install cilium cilium/cilium --version 1.12.5 \
  --namespace kube-system \
  --set nodeinit.enabled=true \
  --set nodeinit.reconfigureKubelet=true \
  --set nodeinit.removeCbrBridge=true \
  --set cni.binPath=/home/kubernetes/bin \
  --set gke.enabled=true \
  --set ipam.mode=kubernetes \
  --set ipv4NativeRoutingCIDR=$NATIVE_CIDR
```

Start observing the events from the Cilium pod:
```bash
tetra getevents -o compact --pod cilium
```

Restart the Cilium agent:
```bash
 kubectl delete pods -n cilium cilium-xpw8x
pod "cilium-xpw8x" deleted
```

An example piece:
```bash
🚀 process cilium/cilium-xpw8x /usr/local/bin/tc filter replace dev lxc_health ingress prio 1 handle 1 bpf da obj 471_next/bpf_lxc.o sec from-container
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SOCKET_FILTER  instruction count 2
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SOCKET_FILTER  instruction count 2
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SOCKET_FILTER test instruction count 2
🗺 bpf_map_alloc cilium/cilium-xpw8x /usr/local/bin/tc BPF_MAP_TYPE_PROG_ARRAY cilium_calls_00 key size 4 value size 4 max entries 33
🗺 bpf_map_alloc cilium/cilium-xpw8x /usr/local/bin/tc BPF_MAP_TYPE_PERCPU_ARRAY cilium_tail_cal key size 4 value size 48 max entries 1
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_CGROUP_SOCK  instruction count 2
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS __send_drop_not instruction count 45
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS tail_handle_ipv instruction count 1383
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS tail_ipv4_ct_eg instruction count 698
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS tail_handle_ipv instruction count 1139
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS tail_handle_arp instruction count 190
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS handle_xgress instruction count 86
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS tail_ipv4_to_en instruction count 1224
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS tail_ipv4_ct_in instruction count 697
🐝 bpf_check cilium/cilium-xpw8x /usr/local/bin/tc BPF_PROG_TYPE_SCHED_CLS handle_policy instruction count 1870
💥 exit    cilium/cilium-xpw8x /usr/local/bin/tc filter replace dev lxc_health ingress prio 1 handle 1 bpf da obj 471_next/bpf_lxc.o sec from-container 0
```