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
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/alecthomas/kingpin/v2"
	"github.com/containerd/cgroups/v3/cgroup1"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/procfs"
)

var (
	collectProc        = kingpin.Flag("collect.proc", "Boolean that sets if to collect proc information").Default("false").Bool()
	CgroupRoot         = kingpin.Flag("path.cgroup.root", "Root path to cgroup fs").Default(defCgroupRoot).String()
	collectProcMaxExec = kingpin.Flag("collect.proc.max-exec", "Max length of process executable to record").Default("100").Int()
	ProcRoot           = kingpin.Flag("path.proc.root", "Root path to proc fs").Default(defProcRoot).String()
	metricLock         = sync.RWMutex{}
)

const (
	Namespace     = "cgroup"
	defCgroupRoot = "/sys/fs/cgroup"
	defProcRoot   = "/proc"
)

type Collector interface {
	// Get new metrics and expose them via prometheus registry.
	Describe(ch chan<- *prometheus.Desc)
	Collect(ch chan<- prometheus.Metric)
}

type Exporter struct {
	paths           []string
	collectError    *prometheus.Desc
	cpuUser         *prometheus.Desc
	cpuSystem       *prometheus.Desc
	cpuTotal        *prometheus.Desc
	cpus            *prometheus.Desc
	cpu_info        *prometheus.Desc
	memoryRSS       *prometheus.Desc
	memoryCache     *prometheus.Desc
	memoryUsed      *prometheus.Desc
	memoryTotal     *prometheus.Desc
	memoryFailCount *prometheus.Desc
	memswUsed       *prometheus.Desc
	memswTotal      *prometheus.Desc
	memswFailCount  *prometheus.Desc
	info            *prometheus.Desc
	processExec     *prometheus.Desc
	logger          log.Logger
	cgroupv2        bool
}

type CgroupMetric struct {
	name            string
	cpuUser         float64
	cpuSystem       float64
	cpuTotal        float64
	cpus            int
	cpu_list        string
	memoryRSS       float64
	memoryCache     float64
	memoryUsed      float64
	memoryTotal     float64
	memoryFailCount float64
	memswUsed       float64
	memswTotal      float64
	memswFailCount  float64
	userslice       bool
	job             bool
	uid             string
	username        string
	jobid           string
	processExec     map[string]float64
	err             bool
}

func NewExporter(paths []string, logger log.Logger, cgroupv2 bool) *Exporter {
	return &Exporter{
		paths: paths,
		cpuUser: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "cpu", "user_seconds"),
			"Cumalitive CPU user seconds for cgroup", []string{"cgroup"}, nil),
		cpuSystem: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "cpu", "system_seconds"),
			"Cumalitive CPU system seconds for cgroup", []string{"cgroup"}, nil),
		cpuTotal: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "cpu", "total_seconds"),
			"Cumalitive CPU total seconds for cgroup", []string{"cgroup"}, nil),
		cpus: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "", "cpus"),
			"Number of CPUs in the cgroup", []string{"cgroup"}, nil),
		cpu_info: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "", "cpu_info"),
			"Information about the cgroup CPUs", []string{"cgroup", "cpus"}, nil),
		memoryRSS: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memory", "rss_bytes"),
			"Memory RSS used in bytes", []string{"cgroup"}, nil),
		memoryCache: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memory", "cache_bytes"),
			"Memory cache used in bytes", []string{"cgroup"}, nil),
		memoryUsed: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memory", "used_bytes"),
			"Memory used in bytes", []string{"cgroup"}, nil),
		memoryTotal: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memory", "total_bytes"),
			"Memory total given to cgroup in bytes", []string{"cgroup"}, nil),
		memoryFailCount: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memory", "fail_count"),
			"Memory fail count", []string{"cgroup"}, nil),
		memswUsed: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memsw", "used_bytes"),
			"Swap used in bytes", []string{"cgroup"}, nil),
		memswTotal: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memsw", "total_bytes"),
			"Swap total given to cgroup in bytes", []string{"cgroup"}, nil),
		memswFailCount: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "memsw", "fail_count"),
			"Swap fail count", []string{"cgroup"}, nil),
		info: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "", "info"),
			"User slice information", []string{"cgroup", "username", "uid", "jobid"}, nil),
		processExec: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "", "process_exec_count"),
			"Count of instances of a given process", []string{"cgroup", "exec"}, nil),
		collectError: prometheus.NewDesc(prometheus.BuildFQName(Namespace, "exporter", "collect_error"),
			"Indicates collection error, 0=no error, 1=error", []string{"cgroup"}, nil),
		logger:   logger,
		cgroupv2: cgroupv2,
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.cpuUser
	ch <- e.cpuSystem
	ch <- e.cpuTotal
	ch <- e.cpus
	ch <- e.cpu_info
	ch <- e.memoryRSS
	ch <- e.memoryCache
	ch <- e.memoryUsed
	ch <- e.memoryTotal
	ch <- e.memoryFailCount
	ch <- e.memswUsed
	ch <- e.memswTotal
	ch <- e.memswFailCount
	ch <- e.info
	if *collectProc {
		ch <- e.processExec
	}
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	metrics, _ := e.getAllMetrics()
	for _, m := range metrics {
		if m.err {
			ch <- prometheus.MustNewConstMetric(e.collectError, prometheus.GaugeValue, 1, m.name)
		}
		ch <- prometheus.MustNewConstMetric(e.cpuUser, prometheus.GaugeValue, m.cpuUser, m.name)
		ch <- prometheus.MustNewConstMetric(e.cpuSystem, prometheus.GaugeValue, m.cpuSystem, m.name)
		ch <- prometheus.MustNewConstMetric(e.cpuTotal, prometheus.GaugeValue, m.cpuTotal, m.name)
		ch <- prometheus.MustNewConstMetric(e.cpus, prometheus.GaugeValue, float64(m.cpus), m.name)
		ch <- prometheus.MustNewConstMetric(e.cpu_info, prometheus.GaugeValue, 1, m.name, m.cpu_list)
		ch <- prometheus.MustNewConstMetric(e.memoryRSS, prometheus.GaugeValue, m.memoryRSS, m.name)
		ch <- prometheus.MustNewConstMetric(e.memoryUsed, prometheus.GaugeValue, m.memoryUsed, m.name)
		ch <- prometheus.MustNewConstMetric(e.memoryTotal, prometheus.GaugeValue, m.memoryTotal, m.name)
		ch <- prometheus.MustNewConstMetric(e.memoryCache, prometheus.GaugeValue, m.memoryCache, m.name)
		ch <- prometheus.MustNewConstMetric(e.memoryFailCount, prometheus.GaugeValue, m.memoryFailCount, m.name)
		ch <- prometheus.MustNewConstMetric(e.memswUsed, prometheus.GaugeValue, m.memswUsed, m.name)
		ch <- prometheus.MustNewConstMetric(e.memswTotal, prometheus.GaugeValue, m.memswTotal, m.name)
		// These metrics currently have no cgroup v2 information
		if !e.cgroupv2 {
			ch <- prometheus.MustNewConstMetric(e.memswFailCount, prometheus.GaugeValue, m.memswFailCount, m.name)
		}
		if m.userslice || m.job {
			ch <- prometheus.MustNewConstMetric(e.info, prometheus.GaugeValue, 1, m.name, m.username, m.uid, m.jobid)
		}
		if *collectProc {
			for exec, count := range m.processExec {
				ch <- prometheus.MustNewConstMetric(e.processExec, prometheus.GaugeValue, count, m.name, exec)
			}
		}
	}
}

func (e *Exporter) getInfo(cgroupName string, metric *CgroupMetric, logger log.Logger) {

	userSlicePattern := regexp.MustCompile("^/user.slice/user-([0-9]+).slice$")
	userSliceMatch := userSlicePattern.FindStringSubmatch(cgroupName)
	if len(userSliceMatch) == 2 {
		metric.userslice = true
		metric.uid = userSliceMatch[1]
		user, err := user.LookupId(metric.uid)
		if err != nil {
			level.Error(logger).Log("msg", "Error looking up user slice uid", "uid", metric.uid, "err", err)
		} else {
			metric.username = user.Username
		}
		return
	}

	slurmPattern := regexp.MustCompile("^/slurm/uid_([0-9]+)/job_([0-9]+)$")
	slurmMatch := slurmPattern.FindStringSubmatch(cgroupName)
	if len(slurmMatch) == 3 {
		metric.job = true
		metric.uid = slurmMatch[1]
		metric.jobid = slurmMatch[2]
		user, err := user.LookupId(metric.uid)
		if err != nil {
			level.Error(logger).Log("msg", "Error looking up slurm uid", "uid", metric.uid, "err", err)
		} else {
			metric.username = user.Username
		}
		return
	}

	torquePattern := regexp.MustCompile("^/torque/([0-9]+).*$")
	torqueMatch := torquePattern.FindStringSubmatch(cgroupName)
	if len(slurmMatch) == 2 {
		metric.job = true
		metric.jobid = torqueMatch[1]
		return

	}

	if *collectProc {
		pids, err := e.getProcesses(cgroupName)
		if err != nil {
			level.Error(e.logger).Log("msg", "Error loading cgroup processes", "cgroup", cgroupName, "err", err)
		}
		getProcInfo(pids, metric, e.logger)
	}
}

func getProcInfo(pids []int, metric *CgroupMetric, logger log.Logger) {
	executables := make(map[string]float64)
	procFS, err := procfs.NewFS(*ProcRoot)
	if err != nil {
		level.Error(logger).Log("msg", "Unable to open procfs", "path", *ProcRoot)
		return
	}
	wg := &sync.WaitGroup{}
	wg.Add(len(pids))
	for _, pid := range pids {
		go func(p int) {
			proc, err := procFS.Proc(p)
			if err != nil {
				level.Error(logger).Log("msg", "Unable to read PID", "pid", p)
				wg.Done()
				return
			}
			executable, err := proc.Executable()
			if err != nil {
				level.Error(logger).Log("msg", "Unable to get executable for PID", "pid", p)
				wg.Done()
				return
			}
			if len(executable) > *collectProcMaxExec {
				level.Debug(logger).Log("msg", "Executable will be truncated", "executable", executable, "len", len(executable), "pid", p)
				trim := *collectProcMaxExec / 2
				executable_prefix := executable[0:trim]
				executable_suffix := executable[len(executable)-trim:]
				executable = fmt.Sprintf("%s...%s", executable_prefix, executable_suffix)
			}
			metricLock.Lock()
			executables[executable] += 1
			metricLock.Unlock()
			wg.Done()
		}(pid)
	}
	wg.Wait()
	metric.processExec = executables
}

func parseCpuSet(cpuset string) ([]string, error) {
	var cpus []string
	var start, end int
	var err error
	if cpuset == "" {
		return nil, nil
	}
	ranges := strings.Split(cpuset, ",")
	for _, r := range ranges {
		boundaries := strings.Split(r, "-")
		if len(boundaries) == 1 {
			start, err = strconv.Atoi(boundaries[0])
			if err != nil {
				return nil, err
			}
			end = start
		} else if len(boundaries) == 2 {
			start, err = strconv.Atoi(boundaries[0])
			if err != nil {
				return nil, err
			}
			end, err = strconv.Atoi(boundaries[1])
			if err != nil {
				return nil, err
			}
		}
		for e := start; e <= end; e++ {
			cpu := strconv.Itoa(e)
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}

func getCPUs(path string, logger log.Logger) ([]string, error) {
	if !fileExists(path) {
		return nil, nil
	}
	cpusData, err := os.ReadFile(path)
	if err != nil {
		level.Error(logger).Log("msg", "Error reading cpuset", "cpuset", path, "err", err)
		return nil, err
	}
	cpus, err := parseCpuSet(strings.TrimSuffix(string(cpusData), "\n"))
	if err != nil {
		level.Error(logger).Log("msg", "Error parsing cpu set", "cpuset", path, "err", err)
		return nil, err
	}
	return cpus, nil
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func (e *Exporter) getProcesses(cgroup string) ([]int, error) {

	var pids []int

	if e.cgroupv2 {
		manager, err := cgroup2.Load(cgroup)
		if err != nil {
			return pids, err
		}
		procs, err := manager.Procs(true)
		if err != nil {
			return pids, err
		}
		pids = make([]int, len(procs))
		for i, p := range procs {
			pids[i] = int(p)
		}
		return pids, nil
	} else {
		manager, err := cgroup1.Load(cgroup1.StaticPath(cgroup))
		if err != nil {
			return pids, err
		}
		pidsCPU, err := manager.Processes(cgroup1.Cpu, true)
		if err != nil {
			return pids, err
		}
		pidsMem, err := manager.Processes(cgroup1.Cpu, true)
		if err != nil {
			return pids, err
		}
		procs := append(pidsCPU, pidsMem...)
		pids = make([]int, len(procs))
		for i, p := range procs {
			pids[i] = int(p.Pid)
		}
		return pids, nil
	}
}

func (e *Exporter) getMetrics(cgroup string) (CgroupMetric, error) {
	if e.cgroupv2 {
		return e.getMetricsv2(cgroup)
	} else {
		return e.getMetricsv1(cgroup)
	}
}

func (e *Exporter) getAllMetrics() ([]CgroupMetric, error) {
	var names []string
	var metrics []CgroupMetric
	for _, cgroup := range e.paths {

		processes, err := e.getProcesses(cgroup)
		if err != nil {
			level.Error(e.logger).Log("msg", "Error loading cgroup processes", "cgroup", cgroup, "err", err)
			metric := CgroupMetric{name: cgroup, err: true}
			metrics = append(metrics, metric)
			continue
		}
		level.Debug(e.logger).Log("msg", "Found processes", "cgroup", cgroup, "processes", len(processes))

		var glob string
		switch cgroup {
		case "/slurm":
			glob = "/slurm/uid_*/job_*"
		case "/user.slice":
			glob = "/user.slice/*"
		case "torque":
			glob = "/torque/*"
		default:
			glob = cgroup + "/*"
		}

		fullPath := filepath.Join(*CgroupRoot + glob)
		groupsPaths, err := filepath.Glob(fullPath)
		if err != nil {
			level.Error(e.logger).Log("msg", "Error loading cgroup children", "cgroup", cgroup, "err", err)
		}
		var children []string
		for _, path := range groupsPaths {
			split := strings.Split(path, *CgroupRoot)
			if len(split) == 2 {
				children = append(children, split[1])
			}
		}

		wg := &sync.WaitGroup{}
		wg.Add(len(names))
		for _, name := range children {
			go func(n string) {
				defer wg.Done()
				metric, _ := e.getMetrics(n)
				metricLock.Lock()
				metrics = append(metrics, metric)
				metricLock.Unlock()
			}(name)
		}
		wg.Wait()
	}
	return metrics, nil
}
