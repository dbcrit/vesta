// SPDX-License-Identifier: Apache-2.0

package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/dbcrit/vesta/host/internal/hostfs"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", "kata-4.2.0", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func realKataConfig(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/kata-4.2.0/configuration-qemu-runtime-rs.toml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// kataDeployDropIn is what kata-deploy writes when proxy settings or guest
// debug need kernel params (install.rs generate_kernel_params_drop_in).
const kataDeployDropIn = `[hypervisor.qemu]
kernel_params = "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1 agent.https_proxy=http://proxy:3128"
`

func TestGoldenKataConfig(t *testing.T) {
	base := realKataConfig(t)
	in := KataConfigInput{
		Base:       base,
		DropIns:    []NamedFile{{Name: "30-kernel-params.toml", Data: []byte(kataDeployDropIn)}},
		KernelPath: "/opt/vesta/kata/0.1.0/vmlinux-vesta",
		ImagePath:  "/opt/vesta/kata/0.1.0/vesta-guest.img",
		Version:    "0.1.0",
	}
	g, err := GenerateKataConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(g.Config) != string(base) {
		t.Fatal("base config was modified; it must be copied verbatim")
	}
	if len(g.DropIns) != 2 || g.DropIns[0].Name != "30-kernel-params.toml" || g.DropIns[1].Name != VestaDropInName {
		t.Fatalf("drop-ins %v", g.DropIns)
	}
	golden(t, "90-vesta.toml.golden", g.DropIns[1].Data)

	// The effective config keeps everything else of the node's config.
	eff, err := effective(g.Config, g.DropIns)
	if err != nil {
		t.Fatal(err)
	}
	q, _ := qemuTable(eff)
	if q["path"] != "/opt/kata/bin/qemu-system-x86_64" || q["shared_fs"] != "virtio-fs" {
		t.Fatalf("unrelated settings changed: path=%v shared_fs=%v", q["path"], q["shared_fs"])
	}
	if q["kernel_params"] != "cgroup_no_v1=all systemd.unified_cgroup_hierarchy=1 agent.https_proxy=http://proxy:3128 lockdown=integrity" {
		t.Fatalf("kernel_params %q", q["kernel_params"])
	}
}

func TestKataConfigEdgeCases(t *testing.T) {
	base := realKataConfig(t)
	mk := func(dropIn string) KataConfigInput {
		in := KataConfigInput{Base: base, KernelPath: "/k", ImagePath: "/i", Version: "1.0.0"}
		if dropIn != "" {
			in.DropIns = []NamedFile{{Name: "50-user.toml", Data: []byte(dropIn)}}
		}
		return in
	}
	t.Run("initrd cleared", func(t *testing.T) {
		g, err := GenerateKataConfig(mk("[hypervisor.qemu]\ninitrd = \"/opt/kata/share/kata-containers/kata-containers-initrd.img\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(g.DropIns[1].Data), "initrd = ''") && !strings.Contains(string(g.DropIns[1].Data), `initrd = ""`) {
			t.Fatalf("initrd not cleared:\n%s", g.DropIns[1].Data)
		}
	})
	t.Run("lockdown replaced", func(t *testing.T) {
		g, err := GenerateKataConfig(mk("[hypervisor.qemu]\nkernel_params = \"lockdown=none quiet\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		var d vestaDropIn
		if err := toml.Unmarshal(g.DropIns[1].Data, &d); err != nil {
			t.Fatal(err)
		}
		if d.Hypervisor.Qemu.KernelParams != "quiet lockdown=integrity" {
			t.Fatalf("kernel_params %q", d.Hypervisor.Qemu.KernelParams)
		}
	})
	t.Run("all annotations stripped", func(t *testing.T) {
		g, err := GenerateKataConfig(mk("[hypervisor.qemu]\nenable_annotations = [\"kernel\", \"image\", \"initrd\", \"path\", \"firmware\", \"kernel_params\", \"default_vcpus\"]\n"))
		if err != nil {
			t.Fatal(err)
		}
		var d vestaDropIn
		_ = toml.Unmarshal(g.DropIns[1].Data, &d)
		if strings.Join(d.Hypervisor.Qemu.EnableAnnotations, ",") != "default_vcpus" {
			t.Fatalf("annotations %v", d.Hypervisor.Qemu.EnableAnnotations)
		}
	})
	for name, dropIn := range map[string]string{
		"lsm without bpf":   "[hypervisor.qemu]\nkernel_params = \"lsm=landlock,yama\"\n",
		"second hypervisor": "[hypervisor.clh]\npath = \"/x\"\n",
		"bad toml":          "[hypervisor.qemu\n",
		"typed wrong":       "[hypervisor.qemu]\nkernel_params = 3\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := GenerateKataConfig(mk(dropIn)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("existing vesta drop-in in base", func(t *testing.T) {
		in := mk("")
		in.DropIns = []NamedFile{{Name: VestaDropInName, Data: []byte("")}}
		if _, err := GenerateKataConfig(in); err == nil {
			t.Fatal("accepted")
		}
	})
}

func TestGoldenContainerdDropIn(t *testing.T) {
	b, err := RenderContainerdDropIn(DefaultHandler, "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2", "/opt/vesta/kata/current/configuration-qemu-vesta.toml", true)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "containerd-vesta.toml.golden", b)
	var nri struct {
		Plugins map[string]struct {
			DefaultValidator struct {
				Enable          bool     `toml:"enable"`
				RequiredPlugins []string `toml:"required_plugins"`
			} `toml:"default_validator"`
		} `toml:"plugins"`
	}
	if err := toml.Unmarshal(b, &nri); err != nil {
		t.Fatal(err)
	}
	if v := nri.Plugins["io.containerd.nri.v1.nri"].DefaultValidator; !v.Enable || len(v.RequiredPlugins) != 0 {
		t.Fatalf("NRI default validator %+v: want enabled, with no global required plugins", v)
	}
	off, err := RenderContainerdDropIn(DefaultHandler, "/x", "/y", false)
	if err != nil || strings.Contains(string(off), "nri") {
		t.Fatalf("validator not disabled: %v\n%s", err, off)
	}
	var doc struct {
		Version int `toml:"version"`
		Plugins map[string]struct {
			Containerd struct {
				Runtimes map[string]struct {
					RuntimeType string   `toml:"runtime_type"`
					RuntimePath string   `toml:"runtime_path"`
					Privileged  bool     `toml:"privileged_without_host_devices"`
					PodAnn      []string `toml:"pod_annotations"`
					Options     struct {
						ConfigPath string `toml:"ConfigPath"`
					} `toml:"options"`
				} `toml:"runtimes"`
			} `toml:"containerd"`
		} `toml:"plugins"`
	}
	if err := toml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	rt := doc.Plugins["io.containerd.cri.v1.runtime"].Containerd.Runtimes["kata-qemu-vesta"]
	if doc.Version != 3 || rt.RuntimeType != "io.containerd.kata-qemu-vesta.v2" || !rt.Privileged ||
		rt.Options.ConfigPath != "/opt/vesta/kata/current/configuration-qemu-vesta.toml" || rt.PodAnn[0] != "io.katacontainers.*" {
		t.Fatalf("parsed %+v", doc)
	}
	if _, err := RenderContainerdDropIn("Bad_Handler", "/x", "/y", false); err == nil {
		t.Fatal("invalid handler accepted")
	}
}

func writeHost(t *testing.T, dir, p, content string, mode os.FileMode) {
	t.Helper()
	full := filepath.Join(dir, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestPlanContainerd(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		version    string
		wantDropIn string
		wantImport string
		wantFlavor Flavor
		wantErr    string
	}{
		{name: "2.4 with conf.d import", version: "containerd://2.4.1",
			files:      map[string]string{containerdConfig: "version = 3\nimports = [\"/etc/containerd/conf.d/*.toml\"]\n"},
			wantDropIn: "/etc/containerd/conf.d/vesta.toml", wantFlavor: FlavorContainerd},
		{name: "2.4 without import", version: "containerd://2.4.1",
			files:      map[string]string{containerdConfig: "version = 3\n"},
			wantDropIn: vestaImportDropIn, wantImport: containerdConfig, wantFlavor: FlavorContainerd},
		{name: "2.1 with conf.d import", version: "containerd://2.1.4",
			files:      map[string]string{containerdConfig: "version = 3\nimports = [\"/etc/containerd/conf.d/*.toml\"]\n"},
			wantDropIn: vestaImportDropIn, wantImport: containerdConfig, wantFlavor: FlavorContainerd},
		{name: "no main config", version: "containerd://2.0.0",
			wantDropIn: vestaImportDropIn, wantImport: containerdConfig, wantFlavor: FlavorContainerd},
		{name: "containerd 1.7", version: "containerd://1.7.27", wantErr: "not supported"},
		{name: "cri-o", version: "cri-o://1.33.0", wantErr: "not containerd"},
		{name: "k3s with import", version: "containerd://2.1.5-k3s1",
			files:      map[string]string{"/var/lib/rancher/k3s/agent/etc/containerd/config.toml": "version = 3\nimports = [\"/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/*.toml\"]\n"},
			wantDropIn: "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/vesta.toml", wantFlavor: FlavorK3s},
		{name: "k3s without import", version: "containerd://2.1.5-k3s1",
			files:   map[string]string{"/var/lib/rancher/k3s/agent/etc/containerd/config.toml": "version = 3\n"},
			wantErr: "does not import"},
		{name: "rke2 v2 template", version: "containerd://2.0.5-k3s1",
			files:   map[string]string{"/var/lib/rancher/rke2/agent/etc/containerd/config.toml": "version = 2\n"},
			wantErr: "version 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for p, c := range tc.files {
				writeHost(t, dir, p, c, 0o644)
			}
			root, _ := hostfs.New(dir)
			plan, err := PlanContainerd(root, tc.version)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.DropInPath != tc.wantDropIn || plan.ImportsConfig != tc.wantImport || plan.Flavor != tc.wantFlavor {
				t.Fatalf("plan %+v", plan)
			}
		})
	}
}

func TestEnsureAndRemoveImport(t *testing.T) {
	dir := t.TempDir()
	orig := "# main config\nversion = 2\n\n[plugins.\"io.containerd.grpc.v1.cri\"]\n  sandbox_image = \"pause:3.10\"\n"
	writeHost(t, dir, containerdConfig, orig, 0o600)
	root, _ := hostfs.New(dir)
	changed, err := EnsureImport(root, containerdConfig, vestaImportDropIn)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	if changed, err = EnsureImport(root, containerdConfig, vestaImportDropIn); err != nil || changed {
		t.Fatal("second EnsureImport changed the file", err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, containerdConfig))
	var doc map[string]any
	if err := toml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["version"] != int64(2) || fmt.Sprint(doc["imports"]) != "["+vestaImportDropIn+"]" {
		t.Fatalf("config %v", doc)
	}
	cri := doc["plugins"].(map[string]any)["io.containerd.grpc.v1.cri"].(map[string]any)
	if cri["sandbox_image"] != "pause:3.10" {
		t.Fatal("unrelated settings lost")
	}
	if fi, _ := os.Stat(filepath.Join(dir, containerdConfig)); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if bak, _ := os.ReadFile(filepath.Join(dir, containerdConfig+backupSuffix)); string(bak) != orig {
		t.Fatal("backup missing or wrong")
	}
	if changed, err = RemoveImport(root, containerdConfig, vestaImportDropIn); err != nil || !changed {
		t.Fatal(changed, err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, containerdConfig))
	if strings.Contains(string(b), "imports") {
		t.Fatalf("import not removed:\n%s", b)
	}
}

// fakeKube implements NodeAPI.
type fakeKube struct {
	mu      sync.Mutex
	crv     string
	labels  map[string]string
	pods    [][]string // successive PodsUsingHandler answers
	podCall int
}

func (f *fakeKube) ContainerRuntimeVersion(context.Context, string) (string, error) {
	return f.crv, nil
}

func (f *fakeKube) SetLabel(_ context.Context, _, k, v string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v == "" {
		delete(f.labels, k)
	} else {
		f.labels[k] = v
	}
	return nil
}

func (f *fakeKube) PodsUsingHandler(context.Context, string, string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.podCall >= len(f.pods) {
		return nil, nil
	}
	f.podCall++
	return f.pods[f.podCall-1], nil
}

type fakeRestarter struct {
	calls int
	err   error
	// errs, if set, is returned per call instead of err.
	errs []error
}

func (f *fakeRestarter) Restart(_ context.Context, units []string) (string, error) {
	f.calls++
	if len(f.errs) >= f.calls {
		return units[0], f.errs[f.calls-1]
	}
	return units[0], f.err
}

// nodeFixture lays out a node with kata-deploy's Kata 4.2 install.
func nodeFixture(t *testing.T, containerdCfg string) string {
	t.Helper()
	dir := t.TempDir()
	writeHost(t, dir, "/opt/kata/VERSION", "4.2.0\n", 0o644)
	writeHost(t, dir, "/opt/kata/runtime-rs/bin/containerd-shim-kata-v2", "#!shim", 0o755)
	writeHost(t, dir, "/opt/kata/"+runtimeConfigRel, string(realKataConfig(t)), 0o644)
	writeHost(t, dir, "/opt/kata/"+path0(runtimeConfigRel)+"/config.d/30-kernel-params.toml", kataDeployDropIn, 0o644)
	if containerdCfg != "" {
		writeHost(t, dir, containerdConfig, containerdCfg, 0o644)
	}
	return dir
}

func path0(p string) string { return filepath.Dir(p) }

func assetsFixture(t *testing.T, version string) *Assets {
	t.Helper()
	dir := t.TempDir()
	var sums strings.Builder
	for n, c := range map[string]string{KernelName: "kernel-" + version, ImageName: "image-" + version} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256([]byte(c))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(s[:]), n)
	}
	if err := os.WriteFile(filepath.Join(dir, SumsName), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, VersionName), []byte(version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := LoadAssets(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func testLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestInstallEndToEnd(t *testing.T) {
	dir := nodeFixture(t, "version = 3\nimports = [\"/etc/containerd/conf.d/*.toml\"]\n")
	root, _ := hostfs.New(dir)
	kube := &fakeKube{crv: "containerd://2.4.1", labels: map[string]string{}}
	rs := &fakeRestarter{}
	opts := Options{Root: root, Assets: assetsFixture(t, "0.1.0"), NodeName: "node-1", Restarter: rs, Kube: kube, Log: testLog()}

	res, err := Install(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AssetsChanged || !res.ContainerdChange || rs.calls != 1 || kube.labels[GuestReadyLabel] != "0.1.0" {
		t.Fatalf("res %+v restarts %d labels %v", res, rs.calls, kube.labels)
	}
	vdir := filepath.Join(dir, "opt/vesta/kata/0.1.0")
	for _, f := range []string{KernelName, ImageName, runtimeConfigName, "config.d/30-kernel-params.toml", "config.d/" + VestaDropInName} {
		fi, err := os.Stat(filepath.Join(vdir, f))
		if err != nil || fi.Mode().Perm() != 0o644 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
	if l, _ := os.Readlink(filepath.Join(dir, "opt/vesta/kata/current")); l != "0.1.0" {
		t.Fatalf("current -> %q", l)
	}
	dropIn, err := os.ReadFile(filepath.Join(dir, "etc/containerd/conf.d/vesta.toml"))
	if err != nil || !strings.Contains(string(dropIn), "/opt/vesta/kata/current/configuration-qemu-vesta.toml") {
		t.Fatalf("drop-in: %v\n%s", err, dropIn)
	}
	// The main config is untouched when conf.d is imported.
	if b, _ := os.ReadFile(filepath.Join(dir, containerdConfig)); strings.Contains(string(b), "vesta") {
		t.Fatal("main containerd config edited")
	}

	// Re-running is idempotent: no restart.
	res, err = Install(context.Background(), opts)
	if err != nil || res.AssetsChanged || res.ContainerdChange || rs.calls != 1 {
		t.Fatalf("second run: %+v restarts=%d err=%v", res, rs.calls, err)
	}

	// Upgrade: the old version stays, current moves.
	opts.Assets = assetsFixture(t, "0.2.0")
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if l, _ := os.Readlink(filepath.Join(dir, "opt/vesta/kata/current")); l != "0.2.0" {
		t.Fatalf("current -> %q", l)
	}
	if _, err := os.Stat(filepath.Join(vdir, KernelName)); err != nil {
		t.Fatal("old version removed on upgrade")
	}
	if kube.labels[GuestReadyLabel] != "0.2.0" || rs.calls != 1 {
		t.Fatalf("labels %v restarts %d (containerd config does not change on upgrade)", kube.labels, rs.calls)
	}

	// Uninstall is refused while pods use the handler.
	kube.pods = [][]string{{"ns/busy"}}
	if err := Uninstall(context.Background(), opts); !errors.Is(err, ErrInUse) {
		t.Fatalf("uninstall with pods: %v", err)
	}
	if kube.labels[GuestReadyLabel] == "" {
		t.Fatal("label removed by a refused uninstall")
	}
	// A pod appearing during uninstall restores the label.
	kube.pods, kube.podCall = [][]string{nil, {"ns/late"}}, 0
	if err := Uninstall(context.Background(), opts); !errors.Is(err, ErrInUse) {
		t.Fatalf("uninstall race: %v", err)
	}
	if kube.labels[GuestReadyLabel] != "0.2.0" {
		t.Fatalf("label not restored: %v", kube.labels)
	}
	kube.pods, kube.podCall = nil, 0
	if err := Uninstall(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if _, ok := kube.labels[GuestReadyLabel]; ok {
		t.Fatal("label kept after uninstall")
	}
	if _, err := os.Stat(filepath.Join(dir, "opt/vesta/kata")); !os.IsNotExist(err) {
		t.Fatal("assets left after uninstall")
	}
	if _, err := os.Stat(filepath.Join(dir, "etc/containerd/conf.d/vesta.toml")); !os.IsNotExist(err) {
		t.Fatal("drop-in left after uninstall")
	}
	if rs.calls != 2 {
		t.Fatalf("restarts %d", rs.calls)
	}
}

func TestInstallImportsPath(t *testing.T) {
	dir := nodeFixture(t, "version = 2\n")
	root, _ := hostfs.New(dir)
	kube := &fakeKube{crv: "containerd://2.1.4", labels: map[string]string{}}
	opts := Options{Root: root, Assets: assetsFixture(t, "0.1.0"), NodeName: "n", Restarter: &fakeRestarter{}, Kube: kube, Log: testLog()}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, containerdConfig))
	if !strings.Contains(string(b), vestaImportDropIn) {
		t.Fatalf("import not added:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, vestaImportDropIn)); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(filepath.Join(dir, containerdConfig))
	if strings.Contains(string(b), vestaImportDropIn) {
		t.Fatalf("import not removed:\n%s", b)
	}
}

func TestInstallRollsBackWhenContainerdFails(t *testing.T) {
	const orig = "version = 2\n# operator comment\n"
	dir := nodeFixture(t, orig)
	root, _ := hostfs.New(dir)
	kube := &fakeKube{crv: "containerd://2.1.4", labels: map[string]string{}}
	rs := &fakeRestarter{errs: []error{errors.New("containerd.service is failed after restart"), nil}}
	_, err := Install(context.Background(), Options{Root: root, Assets: assetsFixture(t, "0.1.0"), NodeName: "n",
		Restarter: rs, Kube: kube, Log: testLog(), NRIValidator: true})
	if err == nil || !strings.Contains(err.Error(), "previous config restored") {
		t.Fatalf("err = %v", err)
	}
	if rs.calls != 2 {
		t.Fatalf("restarts %d, want 2 (new config, then the restored one)", rs.calls)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, containerdConfig)); string(b) != orig {
		t.Fatalf("containerd config not restored:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, vestaImportDropIn)); !os.IsNotExist(err) {
		t.Fatal("drop-in left behind after rollback")
	}
	if _, ok := kube.labels[GuestReadyLabel]; ok {
		t.Fatal("node labelled after a failed install")
	}
}

func TestInstallFailuresRemoveLabel(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(t *testing.T, dir string)
		crv     string
		restart error
		wantErr string
	}{
		{name: "no kata", mutate: func(t *testing.T, dir string) { os.RemoveAll(filepath.Join(dir, "opt/kata")) }, wantErr: "shim not found"},
		{name: "kata 3", mutate: func(t *testing.T, dir string) { writeHost(t, dir, "/opt/kata/VERSION", "3.19.1", 0o644) }, wantErr: "not supported"},
		{name: "shim not executable", mutate: func(t *testing.T, dir string) {
			os.Chmod(filepath.Join(dir, "opt/kata", shimRelPath), 0o644)
		}, wantErr: "not an executable"},
		{name: "symlinked config dir", mutate: func(t *testing.T, dir string) {
			d := filepath.Join(dir, "opt/kata/share/defaults/kata-containers/runtime-rs/runtimes")
			os.RemoveAll(d)
			os.Symlink(t.TempDir(), d)
			os.Remove(filepath.Join(dir, "opt/kata", pristineConfigRel))
		}, wantErr: "symlink"},
		{name: "old containerd", crv: "containerd://1.7.20", wantErr: "not supported"},
		{name: "restart fails", restart: errors.New("unit failed"), wantErr: "unit failed"},
		{name: "planted symlink in vesta prefix", mutate: func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "opt"), 0o755)
			os.Symlink(t.TempDir(), filepath.Join(dir, "opt/vesta"))
		}, wantErr: "unsafe path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := nodeFixture(t, "version = 3\nimports = [\"/etc/containerd/conf.d/*.toml\"]\n")
			if tc.mutate != nil {
				tc.mutate(t, dir)
			}
			root, _ := hostfs.New(dir)
			crv := tc.crv
			if crv == "" {
				crv = "containerd://2.4.1"
			}
			kube := &fakeKube{crv: crv, labels: map[string]string{GuestReadyLabel: "0.0.9"}}
			_, err := Install(context.Background(), Options{Root: root, Assets: assetsFixture(t, "0.1.0"), NodeName: "n",
				Restarter: &fakeRestarter{err: tc.restart}, Kube: kube, Log: testLog()})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if _, ok := kube.labels[GuestReadyLabel]; ok {
				t.Fatal("stale label kept after a failed install")
			}
		})
	}
}

func TestInstallRefusesChangedAssetsForSameVersion(t *testing.T) {
	dir := nodeFixture(t, "version = 3\nimports = [\"/etc/containerd/conf.d/*.toml\"]\n")
	root, _ := hostfs.New(dir)
	kube := &fakeKube{crv: "containerd://2.4.1", labels: map[string]string{}}
	opts := Options{Root: root, Assets: assetsFixture(t, "0.1.0"), NodeName: "n", Restarter: &fakeRestarter{}, Kube: kube, Log: testLog()}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	writeHost(t, dir, "/opt/vesta/kata/0.1.0/"+KernelName, "tampered", 0o644)
	if _, err := Install(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoadAssetsValidation(t *testing.T) {
	good := assetsFixture(t, "1.2.3-rc.1")
	if good.Version != "1.2.3-rc.1" {
		t.Fatal(good.Version)
	}
	for _, v := range []string{"1.2", "v1.2.3", "1.2.3+build", "../1.2.3", strings.Repeat("1", 70) + ".0.0"} {
		if _, err := LoadAssets(good.Dir, v); err == nil {
			t.Errorf("version %q accepted", v)
		}
	}
	for name, sums := range map[string]string{
		"missing image":  strings.Repeat("a", 64) + "  " + KernelName + "\n",
		"extra file":     strings.Repeat("a", 64) + "  " + KernelName + "\n" + strings.Repeat("b", 64) + "  " + ImageName + "\n" + strings.Repeat("c", 64) + "  ../etc/passwd\n",
		"malformed":      "xyz  " + KernelName + "\n",
		"listed twice":   strings.Repeat("a", 64) + "  " + KernelName + "\n" + strings.Repeat("a", 64) + "  " + KernelName + "\n",
		"uppercase hash": strings.Repeat("A", 64) + "  " + KernelName + "\n" + strings.Repeat("b", 64) + "  " + ImageName + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			os.WriteFile(filepath.Join(d, SumsName), []byte(sums), 0o644)
			if _, err := LoadAssets(d, "1.0.0"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
