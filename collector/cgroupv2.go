// Copyright 2020 Trey Dockendorf
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/go-kit/log/level"
)

func getStatv2(name string, path string) (float64, error) {
	if !fileExists(path) {
		return 0, fmt.Errorf("path %s does not exist", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.Fields(s.Text())
		if len(parts) != 2 {
			return 0, cgroup2.ErrInvalidFormat
		}
		v, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			return 0, cgroup2.ErrInvalidFormat
		}
		if parts[0] == name {
			return float64(v), nil
		}
	}
	return 0, fmt.Errorf("unable to find stat key %s in %s", name, path)
}

func (e *Exporter) getMetricsv2(cgroup string) (metric CgroupMetric, err error) {
	metric.name = cgroup
	level.Debug(e.logger).Log("msg", "Loading cgroup", "path", cgroup)

	manager, err := cgroup2.Load(cgroup)
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to load cgroups", "path", cgroup, "err", err)
		metric.err = true
		return
	}

	stats, err := manager.Stat()
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to get cgroup stats", "path", cgroup)
		metric.err = true
		return
	}

	if stats == nil {
		level.Error(e.logger).Log("msg", "Cgroup stats are nil", "path", cgroup)
		metric.err = true
		return
	}

	if stats.CPU != nil {
		metric.cpuUser = float64(stats.CPU.UserUsec) / 1000000.0
		metric.cpuSystem = float64(stats.CPU.SystemUsec) / 1000000.0
		metric.cpuTotal = float64(stats.CPU.UsageUsec) / 1000000.0
	}

	// TODO: Move to https://github.com/containerd/cgroups/blob/d131035c7599c51ff4aed27903c45eb3b2cc29d0/cgroup2/manager.go#L593
	// see https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt section 5.5
	memoryStatPath := filepath.Join(*CgroupRoot, cgroup, "memory.stat")
	swapcached, err := getStatv2("swapcached", memoryStatPath)
	if err != nil {
		level.Error(e.logger).Log("msg", "Unable to get swapcached", "path", cgroup, "err", err)
		metric.err = true
		return
	}

	if stats.Memory != nil {
		metric.memoryRSS = float64(stats.Memory.Anon) + swapcached + float64(stats.Memory.AnonThp)
		metric.memoryUsed = float64(stats.Memory.Usage)
		metric.memoryTotal = float64(stats.Memory.UsageLimit)
		metric.memoryCache = float64(stats.Memory.File)
		metric.memswUsed = float64(stats.Memory.SwapUsage)
		metric.memswTotal = float64(stats.Memory.SwapLimit)
		if stats.MemoryEvents != nil {
			metric.memoryFailCount = float64(stats.MemoryEvents.Oom)
		}
	}

	// TODO: cpuset.cpus.effective?
	cpusPath := filepath.Join(*CgroupRoot, cgroup, "cpuset.cpus")
	if cpus, err := getCPUs(cpusPath, e.logger); err == nil {
		metric.cpus = len(cpus)
		metric.cpu_list = strings.Join(cpus, ",")
	}

	e.getInfo(cgroup, &metric, e.logger)
	return metric, nil
}
