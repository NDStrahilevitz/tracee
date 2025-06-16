package ebpf

import (
	"context"
	"encoding/binary"
	"sort"
	"time"
	"unsafe"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
)

// eventStatsValues mirrors the C struct event_stats_values (event_stats_values_t).
type eventStatsValues struct {
	submitAttempts uint64
	submitFailures uint64
}

// countPerfEventSubmissions is a goroutine that periodically counts the
// number of attempts and failures to submit events to the perf buffer
func (t *Tracee) countPerfEventSubmissions(ctx context.Context) {
	logger.Debugw("Starting countPerfEventSubmissions goroutine")
	defer logger.Debugw("Stopped countPerfEventSubmissions goroutine")

	evtsCountsBPFMap, err := t.bpfModule.GetMap("events_stats")
	if err != nil {
		logger.Errorw("Failed to get events_stats map", "error", err)
		return
	}

	evtStatZero := eventStatsValues{}
	for _, id := range t.policyManager.EventsToSubmit() {
		if id >= events.MaxCommonID {
			continue
		}

		key := uint32(id)
		err := evtsCountsBPFMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&evtStatZero))
		if err != nil {
			logger.Errorw("Failed to update events_stats map", "error", err)
		}
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.stats.BPFPerfEventSubmitAttemptsCount.Reset()
			t.stats.BPFPerfEventSubmitFailuresCount.Reset()

			// Get the counts of each event from the BPF map
			iter := evtsCountsBPFMap.Iterator()
			for iter.Next() {
				key := binary.LittleEndian.Uint32(iter.Key())
				value, err := evtsCountsBPFMap.GetValue(unsafe.Pointer(&key))
				if err != nil {
					logger.Errorw("Failed to get value from events_stats map", "error", err)
					continue
				}

				// Get counts
				id := events.ID(key)
				attempts := binary.LittleEndian.Uint64(value[0:8])
				failures := binary.LittleEndian.Uint64(value[8:16])
				t.stats.BPFPerfEventSubmitAttemptsCount.Set(id, attempts)
				t.stats.BPFPerfEventSubmitFailuresCount.Set(id, failures)

				// Update Prometheus metrics for current event
				evtName := events.Core.GetDefinitionByID(id).GetName()
				t.stats.BPFPerfEventSubmitAttemptsCount.GaugeVec().WithLabelValues(evtName).Set(float64(attempts))
				t.stats.BPFPerfEventSubmitFailuresCount.GaugeVec().WithLabelValues(evtName).Set(float64(failures))
			}

			// Log the counts
			t.stats.BPFPerfEventSubmitAttemptsCount.Log()
			t.stats.BPFPerfEventSubmitFailuresCount.Log()
		}
	}
}

type cpuBufsSubmitAttempts struct {
	submitAttempts uint64
	submitFailures uint64
}

func (t *Tracee) countCpuBufsSubmitAttempts(ctx context.Context) {
	logger.Debugw("Starting countCpuBufsSubmitAttempts goroutine")
	defer logger.Debugw("Stopped countCpuBufsSubmitAttempts goroutine")

	cpuBufsSubmitAttemptsBPFMap, err := t.bpfModule.GetMap("cpu_bufs_submit_attempts_map")
	if err != nil {
		logger.Errorw("Failed to get cpu_bufs_submit_attempts_map map", "error", err)
		return
	}

	for i := 0; i < 32; i++ {
		zero := cpuBufsSubmitAttempts{}
		err = cpuBufsSubmitAttemptsBPFMap.Update(unsafe.Pointer(&i), unsafe.Pointer(&zero))
		if err != nil {
			logger.Errorw("Failed to update cpu_bufs_submit_attempts_map map", "error", err, "cpu", i)
		}
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cpuAttemptCounts := make(map[uint16]uint64)
			cpuFailureCounts := make(map[uint16]uint64)

			iter := cpuBufsSubmitAttemptsBPFMap.Iterator()
			for iter.Next() {
				key := binary.LittleEndian.Uint16(iter.Key())
				value, err := cpuBufsSubmitAttemptsBPFMap.GetValue(unsafe.Pointer(&key))
				if err != nil {
					logger.Errorw("Failed to get value from cpu_bufs_submit_attempts_map map", "error", err)
					continue
				}

				attempts := binary.LittleEndian.Uint64(value[0:8])
				failures := binary.LittleEndian.Uint64(value[8:16])
				cpuAttemptCounts[key] = attempts
				cpuFailureCounts[key] = failures
			}
			// sort and log by key
			keys := make([]uint16, 0, len(cpuAttemptCounts))
			for k := range cpuAttemptCounts {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				return keys[i] < keys[j]
			})

			for _, k := range keys {
				logger.Infow("CPU buffer submit attempts", "cpu", k, "attempts", cpuAttemptCounts[k])
				logger.Infow("CPU buffer submit failures", "cpu", k, "failures", cpuFailureCounts[k])
			}
		}
	}
}
