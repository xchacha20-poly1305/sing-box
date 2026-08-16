//go:build with_ebpf && (linux || android)

package ebpf

import (
	"fmt"
	"io"
	"strings"
)

func WriteKernelProbeReport(writer io.Writer, report *KernelProbeReport) error {
	if _, err := fmt.Fprintln(writer, "sing-box eBPF inbound kernel capability probe"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Platform: %s; kernel: %s; architecture: %s; mode: %s; network: %s\n",
		report.Platform, report.KernelRelease, report.Architecture, report.Mode, strings.Join(report.Network, ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "Runtime feature probe: cilium/ebpf direct bpf(2) probes (no shell, bpftool, or tc dependency)"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "The probe does not attach programs or change qdiscs, routes, sysctls, cgroups, or traffic."); err != nil {
		return err
	}

	lastScope := ""
	for _, finding := range report.Findings {
		if finding.Scope != lastScope {
			if _, err := fmt.Fprintf(writer, "\n%s\n", kernelProbeScopeTitle(finding.Scope)); err != nil {
				return err
			}
			lastScope = finding.Scope
		}
		if _, err := fmt.Fprintf(writer, "%-7s [%-14s] [%-11s] %s\n        %s\n",
			finding.Status, finding.Scope, finding.Importance, finding.Feature, finding.Detail); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintln(writer, "\nActive sing-box eBPF programs"); err != nil {
		return err
	}
	if report.ActiveStateErr != nil {
		if _, err := fmt.Fprintln(writer, "  UNKNOWN: program enumeration was inconclusive:", shortProbeError(report.ActiveStateErr)); err != nil {
			return err
		}
	} else if len(report.ActivePrograms) == 0 {
		if _, err := fmt.Fprintln(writer, "  none visible"); err != nil {
			return err
		}
	} else {
		for _, program := range report.ActivePrograms {
			if _, err := fmt.Fprintf(writer, "  id=%d name=%s type=%s maps=%d\n",
				program.ID, program.Name, program.Type, program.MapCount); err != nil {
				return err
			}
		}
	}

	counts := report.Counts()
	if _, err := fmt.Fprintf(writer, "\nSummary: PASS=%d WARN=%d FAIL=%d UNKNOWN=%d\n",
		counts[KernelProbePass], counts[KernelProbeWarn], counts[KernelProbeFail], counts[KernelProbeUnknown]); err != nil {
		return err
	}
	if failures := report.RequiredFailures(); failures > 0 {
		_, err := fmt.Fprintf(writer, "Result: unsupported for at least one selected data path (%d required check(s) failed).\n", failures)
		return err
	}
	if counts[KernelProbeUnknown] > 0 || report.ActiveStateErr != nil {
		_, err := fmt.Fprintln(writer, "Result: no required failure was proven, but UNKNOWN checks need more privileges or a real sing-box startup test.")
		return err
	}
	_, err := fmt.Fprintln(writer, "Result: all selected checks passed or have a documented compatibility fallback.")
	return err
}

func kernelProbeScopeTitle(scope string) string {
	switch scope {
	case "common":
		return "Common prerequisites"
	case "local":
		return "Local cgroup data path"
	case "shared-network":
		return "Shared-network TC gateway data path"
	default:
		return scope
	}
}
