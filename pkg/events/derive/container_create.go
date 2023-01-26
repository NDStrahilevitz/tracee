package derive

import (
	"fmt"

	"github.com/aquasecurity/tracee/pkg/cgroup"
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/types/trace"
)

// ContainerCreate receives a containers as a closure argument to track it's containers.
// If it receives a cgroup_mkdir event, it can derive a container_create event from it.
func ContainerCreate(containers *containers.Containers) deriveFunction {
	return deriveSingleEvent(events.ContainerCreate, deriveContainerCreateArgs(containers))
}

func deriveContainerCreateArgs(containers *containers.Containers) func(event trace.Event) ([]interface{}, error) {
	return func(event trace.Event) ([]interface{}, error) {
		// if cgroup_id is from non default hid (v1 case), the cgroup info query will fail, so we skip
		cgroupPath, err := parse.ArgVal[string](&event, "cgroup_path")
		if event.MatchedScopes == uint64(0) {
			logger.Warn("[container_create.go] cgroup mkdir with zeroed scopes", "cgroup_path", cgroupPath)
		}
		if err != nil {
			return nil, err
		}
		if check, err := isCgroupEventInHid(&event, containers); !check {
			return nil, err
		}
		cgroupId, err := parse.ArgVal[uint64](&event, "cgroup_id")
		if err != nil {
			return nil, err
		}
		if info := containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			logger.Info("container id", "path", cgroupPath, "id", info.Container.ContainerId, "cgroup_mkdir scopes", fmt.Sprintf("0x%016x", event.MatchedScopes))
			args := []interface{}{
				info.Runtime.String(),
				info.Container.ContainerId,
				info.Ctime.UnixNano(),
				info.Container.Image,
				info.Container.Name,
				info.Container.Pod.Name,
				info.Container.Pod.Namespace,
				info.Container.Pod.UID,
				info.Container.Pod.Sandbox,
			}
			return args, nil
		}
		logger.Warn("no container id", "path", cgroupPath)

		return nil, nil
	}
}

// isCgroupEventInHid checks if cgroup event is relevant for deriving container event in it's hierarchy id.
// in tracee we only care about containers inside the cpuset controller, as such other hierarchy ids will lead
// to a failed query.
func isCgroupEventInHid(event *trace.Event, containers *containers.Containers) (bool, error) {
	if containers.GetCgroupVersion() == cgroup.CgroupVersion2 {
		return true, nil
	}
	hierarchyID, err := parse.ArgVal[uint32](event, "hierarchy_id")
	if err != nil {
		return false, err
	}
	return containers.GetDefaultCgroupHierarchyID() == int(hierarchyID), nil
}
