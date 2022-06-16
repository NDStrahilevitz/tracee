package tracee.TRC_15

import data.tracee.helpers

__rego_metadoc__ := {
	"id": "TRC-15",
	"version": "0.1.0",
	"name": "Hooking system calls by overriding the system call table entries",
	"description": "Usage of kernel modules to hook system calls",
	"tags": ["linux"],
	"properties": {
		"Severity": 4,
		"MITRE ATT&CK": "Persistence: Hooking system calls entries in the system-call table",
	},
}

eventSelectors := [{
	"source": "tracee",
	"name": "hooked_syscalls",
}]

tracee_selected_events[eventSelector] {
	eventSelector := eventSelectors[_]
}

filters := [
	{
		"field": "event",
		"operator": 0, #Equal
		"value": ["hooked_syscalls"]
	},
	{
		#test for hooked_syscalls != [] so non empty
		"field": "hooked_syscalls.args.hooked_syscalls",
		"operator": 1,
		"value": ["[]"]
	},
	{
		"field": "execve.args.envp",
		"operator": 0,
		"value": ["*LD_PRELOAD*", "*LD_LIBRARY_PATH"]
	},
]

signature_filters[filter] {
	filter := filters[_]
}

tracee_match = res {
	input.eventName == "hooked_syscalls"
	hooked_syscalls_arr := helpers.get_tracee_argument("hooked_syscalls")
	c := count(hooked_syscalls_arr)
	c > 0
	res := {"hooked syscall": hooked_syscalls_arr}
}
