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
	"fmt"
	"strings"

	"github.com/containerd/cgroups/v3/cgroup1"
	"github.com/go-kit/log/level"
)

func (e *Exporter) getMetricsv1(cgroup string) (metric CgroupMetric, err error) {
	metric.name = cgroup
	level.Debug(e.logger).Log("msg", "Loading cgroup", "root", *CgroupRoot, "path", cgroup)

	manager, err := cgroup1.Load(cgroup1.StaticPath(cgroup))
	if err != nil {
		level.Error(e.logger).Log("msg", "Failed to load cgroups", "path", cgroup, "err", err)
		metric.err = true
		return
	}

	stats, err := manager.Stat(cgroup1.IgnoreNotExist)
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

	if stats.CPU != nil && stats.CPU.Usage != nil {
		metric.cpuUser = float64(stats.CPU.Usage.User) / 1000000000.0
		metric.cpuSystem = float64(stats.CPU.Usage.Kernel) / 1000000000.0
		metric.cpuTotal = float64(stats.CPU.Usage.Total) / 1000000000.0
	}

	if stats.Memory != nil {
		metric.memoryRSS = float64(stats.Memory.TotalRSS)
		metric.memoryCache = float64(stats.Memory.TotalCache)
		if stats.Memory.Usage != nil {
			metric.memoryUsed = float64(stats.Memory.Usage.Usage)
			metric.memoryTotal = float64(stats.Memory.Usage.Limit)
			metric.memoryFailCount = float64(stats.Memory.Usage.Failcnt)
		}
		if stats.Memory.Swap != nil {
			metric.memswUsed = float64(stats.Memory.Swap.Usage)
			metric.memswTotal = float64(stats.Memory.Swap.Limit)
			metric.memswFailCount = float64(stats.Memory.Swap.Failcnt)
		}
	}

	cpusPath := fmt.Sprintf("%s/cpuset%s/cpuset.cpus", *CgroupRoot, cgroup)
	if cpus, err := getCPUs(cpusPath, e.logger); err == nil {
		metric.cpus = len(cpus)
		metric.cpu_list = strings.Join(cpus, ",")
	}

	e.getInfo(cgroup, &metric, e.logger)
	return metric, nil
}
