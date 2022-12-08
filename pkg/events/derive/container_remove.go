package derive

import (
	"github.com/aquasecurity/tracee/pkg/containers"
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

// ContainerRemove receives a containers.Containers object as a closure argument to track it's containers.
// If it receives a cgroup_rmdir event, it can derive a container_remove event from it.
func ContainerRemove(containers *containers.Containers) deriveFunction {
	return deriveSingleEvent(events.ContainerRemove, deriveContainerRemoveArgs(containers))
}

func deriveContainerRemoveArgs(containers *containers.Containers) deriveArgsFunction {
	return func(event trace.Event) ([]interface{}, error) {
		// skip check for unrelated cgroups hids (see container_create.go)
		if check, err := isCgroupEventInHid(&event, containers); !check {
			return nil, err
		}
		cgroupId, err := parse.ArgUint64Val(&event, "cgroup_id")
		if err != nil {
			return nil, err
		}
		if info := containers.GetCgroupInfo(cgroupId); info.Container.ContainerId != "" {
			return []interface{}{info.Runtime.String(), info.Container.ContainerId}, nil
		}
		return nil, nil
	}
}
