package exporter

const (
	perfEventRoot       = "/sys/fs/cgroup/perf_event"
	guaranteePodSubPath = "/kubepods.slice/"
	burstablePodSubPath = "/kubepods.slice/kubepods-burstable.slice/"
)
