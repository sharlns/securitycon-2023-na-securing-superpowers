ARG UBUNTU_IMAGE=docker.io/library/ubuntu:22.10
ARG CILIUM_BPFTOOL_IMAGE=quay.io/cilium/cilium-bpftool:78448c1a37ff2b790d5e25c3d8b8ec3e96e6405f@sha256:99a9453a921a8de99899ef82e0822f0c03f65d97005c064e231c06247ad8597d

FROM ${CILIUM_BPFTOOL_IMAGE} as bpftool-dist

FROM ${UBUNTU_IMAGE}
COPY --from=bpftool-dist /usr/local /usr/local
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y libcap-ng-utils libelf-dev libcap2-bin curl

COPY create-bpf-programs.sh /
COPY seattle_bpf_prog.o /
CMD ["./create-bpf-programs.sh"]