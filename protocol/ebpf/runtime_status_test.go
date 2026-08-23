//go:build with_ebpf && (linux || android)

package ebpf

import (
	"encoding/json"
	"testing"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

func TestEBPFRuntimeStatusJSON(t *testing.T) {
	inbound := &Inbound{
		cgroupEnabled:        true,
		sharedNetworkEnabled: true,
	}
	inbound.diagnostics.localUDPRedirectRecovery.Add(2)
	inbound.diagnostics.localUDPConnectedRecovery.Add(3)
	inbound.diagnostics.localUDPBindingRecovery.Add(4)
	inbound.diagnostics.localUDPLateReply.Add(5)
	encoded, err := json.Marshal(inbound.runtimeStatus("test"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Mode        string `json:"mode"`
		Phase       string `json:"phase"`
		Diagnostics struct {
			Local struct {
				UDPRedirectRecovery  uint64 `json:"udp_redirect_recovery"`
				UDPConnectedRecovery uint64 `json:"udp_connected_recovery"`
				UDPBindingRecovery   uint64 `json:"udp_binding_recovery"`
				UDPLateReply         uint64 `json:"udp_late_reply"`
			} `json:"local"`
		} `json:"diagnostics"`
	}
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Mode != ebpfModeHybrid || decoded.Phase != "test" ||
		decoded.Diagnostics.Local.UDPRedirectRecovery != 2 ||
		decoded.Diagnostics.Local.UDPConnectedRecovery != 3 ||
		decoded.Diagnostics.Local.UDPBindingRecovery != 4 ||
		decoded.Diagnostics.Local.UDPLateReply != 5 {
		t.Fatalf("unexpected runtime status: %+v", decoded)
	}
}

func TestCgroupUDPMapPressure(t *testing.T) {
	if _, pressured := cgroupUDPMapPressure([]ECommon.RuntimeMapStatus{{
		Name:         "cgroup_udp_redirect",
		Type:         "Hash",
		Entries:      58983,
		Capacity:     65536,
		EntriesKnown: true,
	}}); !pressured {
		t.Fatal("expected 90 percent hash-map pressure")
	}
	for _, mapStatus := range []ECommon.RuntimeMapStatus{
		{Name: "cgroup_udp_redirect", Type: "Hash", Entries: 58982, Capacity: 65536, EntriesKnown: true},
		{Name: "cgroup_udp_redirect", Type: "LRUHash", Entries: 65536, Capacity: 65536, EntriesKnown: true},
		{Name: "unrelated", Type: "Hash", Entries: 65536, Capacity: 65536, EntriesKnown: true},
	} {
		if _, pressured := cgroupUDPMapPressure([]ECommon.RuntimeMapStatus{mapStatus}); pressured {
			t.Fatalf("unexpected map pressure warning: %+v", mapStatus)
		}
	}
}
