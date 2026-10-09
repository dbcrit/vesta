// SPDX-License-Identifier: Apache-2.0

// Package install implements vesta-install, the init container that installs
// the kata-qemu-vesta runtime on a Kata node (ARCHITECTURE §2.2 "Guest image
// distribution"): check Kata, install the guest kernel and image, generate
// the runtime config, register the containerd handler and label the node.
// All host writes go through hostfs (no symlink following, atomic renames).
package install

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/dbcrit/vesta/host/internal/hostfs"
)

// Node paths (contract: /opt/vesta/kata/<version>/..., current symlink).
const (
	DefaultKataPrefix  = "/opt/kata"
	DefaultVestaPrefix = "/opt/vesta"
	DefaultHandler     = "kata-qemu-vesta"
	runtimeConfigName  = "configuration-qemu-vesta.toml"
)

// Options configures Install and Uninstall.
type Options struct {
	Root        *hostfs.Root
	Assets      *Assets // Install only
	NodeName    string
	Handler     string
	KataPrefix  string
	VestaPrefix string
	Restarter   Restarter
	Kube        NodeAPI
	Log         *slog.Logger
	// NRIValidator enables containerd's NRI default validator in the drop-in
	// (see RenderContainerdDropIn).
	NRIValidator bool
}

func (o *Options) defaults() error {
	if o.Handler == "" {
		o.Handler = DefaultHandler
	}
	if o.KataPrefix == "" {
		o.KataPrefix = DefaultKataPrefix
	}
	if o.VestaPrefix == "" {
		o.VestaPrefix = DefaultVestaPrefix
	}
	switch {
	case o.Root == nil || o.Kube == nil || o.Restarter == nil || o.Log == nil:
		return errors.New("install: root, kube, restarter and log are required")
	case !ValidHandler(o.Handler):
		return fmt.Errorf("invalid handler %q", o.Handler)
	case len(validation.IsDNS1123Subdomain(o.NodeName)) > 0:
		return fmt.Errorf("invalid node name %q", o.NodeName)
	}
	for _, p := range []string{o.KataPrefix, o.VestaPrefix} {
		if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
			return fmt.Errorf("prefix %q must be an absolute, clean directory", p)
		}
	}
	return nil
}

func (o *Options) kataDir() string            { return o.VestaPrefix + "/kata" }
func (o *Options) versionDir(v string) string { return o.kataDir() + "/" + v }
func (o *Options) currentLink() string        { return o.kataDir() + "/current" }

// ConfigPath is the containerd options.ConfigPath: through the current
// symlink, which Kata canonicalizes, so config.d is found in the version
// directory.
func (o *Options) ConfigPath() string { return o.currentLink() + "/" + runtimeConfigName }

// Result summarizes an install.
type Result struct {
	Version          string
	KataVersion      string
	Flavor           Flavor
	AssetsChanged    bool
	ContainerdChange bool
	RestartedUnit    string
}

// Install performs the installation. On any failure before the node is
// labelled, a stale guest-ready label is removed so no new vesta pods land
// on a node that cannot run them.
func Install(ctx context.Context, o Options) (*Result, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	if o.Assets == nil {
		return nil, errors.New("install: assets are required")
	}
	res, err := install(ctx, &o)
	if err != nil {
		if lerr := o.Kube.SetLabel(ctx, o.NodeName, GuestReadyLabel, ""); lerr != nil {
			o.Log.Warn("could not remove stale guest-ready label", "err", lerr)
		}
		return res, err
	}
	return res, nil
}

func install(ctx context.Context, o *Options) (*Result, error) {
	log := o.Log
	res := &Result{Version: o.Assets.Version}

	crv, err := o.Kube.ContainerRuntimeVersion(ctx, o.NodeName)
	if err != nil {
		return res, err
	}
	plan, err := PlanContainerd(o.Root, crv)
	if err != nil {
		return res, fmt.Errorf("containerd: %w", err)
	}
	res.Flavor = plan.Flavor

	kata, err := DetectKata(o.Root, o.KataPrefix)
	if err != nil {
		return res, fmt.Errorf("kata: %w", err)
	}
	res.KataVersion = kata.Version
	if kata.Version == "" {
		log.Warn("kata version unknown (no VERSION file); assuming the runtime-rs 4.x layout", "tested", TestedKataVersion)
	} else if kata.Version != TestedKataVersion {
		log.Warn("kata version differs from the tested release", "kata", kata.Version, "tested", TestedKataVersion)
	}
	log.Info("found kata", "version", kata.Version, "config", kata.ConfigPath, "drop_ins", len(kata.DropIns), "containerd", crv, "flavor", plan.Flavor)

	vdir := o.versionDir(o.Assets.Version)
	if err := o.Root.MkdirAll(vdir); err != nil {
		return res, fmt.Errorf("create %s: %w", vdir, err)
	}
	if res.AssetsChanged, err = InstallAssets(o.Root, o.Assets, vdir); err != nil {
		return res, err
	}

	gen, err := GenerateKataConfig(KataConfigInput{
		Base: kata.Config, DropIns: kata.DropIns,
		KernelPath: vdir + "/" + KernelName, ImagePath: vdir + "/" + ImageName,
		Version: o.Assets.Version,
	})
	if err != nil {
		return res, fmt.Errorf("generate kata config: %w", err)
	}
	if err := writeRuntimeConfig(o.Root, vdir, gen); err != nil {
		return res, err
	}

	// Relative target: the link stays valid wherever the host root is
	// mounted.
	if _, err := o.Root.SwapSymlink(o.currentLink(), o.Assets.Version); err != nil {
		return res, fmt.Errorf("switch current version: %w", err)
	}

	dropIn, err := RenderContainerdDropIn(o.Handler, path.Join(o.KataPrefix, shimRelPath), o.ConfigPath(), o.NRIValidator)
	if err != nil {
		return res, err
	}
	// Kept to roll back if containerd does not come up with the new config.
	saved := []savedFile{}
	for _, p := range []string{plan.DropInPath, plan.ImportsConfig} {
		if p == "" {
			continue
		}
		sf, err := saveFile(o.Root, p)
		if err != nil {
			return res, err
		}
		saved = append(saved, sf)
	}
	changed, err := o.Root.WriteFile(plan.DropInPath, dropIn, 0o644)
	if err != nil {
		return res, fmt.Errorf("write containerd drop-in: %w", err)
	}
	if plan.ImportsConfig != "" {
		imp, err := EnsureImport(o.Root, plan.ImportsConfig, plan.DropInPath)
		if err != nil {
			return res, fmt.Errorf("containerd imports: %w", err)
		}
		changed = changed || imp
	}
	res.ContainerdChange = changed
	if changed {
		log.Info("containerd config changed; restarting", "drop_in", plan.DropInPath, "units", plan.Units)
		unit, err := o.Restarter.Restart(ctx, plan.Units)
		res.RestartedUnit = unit
		if err != nil {
			if errors.Is(err, ErrRestartRequired) {
				return res, fmt.Errorf("restart containerd: %w", err)
			}
			return res, rollback(ctx, o, plan, saved, err)
		}
	}

	if err := o.Kube.SetLabel(ctx, o.NodeName, GuestReadyLabel, o.Assets.Version); err != nil {
		return res, err
	}
	log.Info("vesta runtime installed", "version", o.Assets.Version, "handler", o.Handler, "config", o.ConfigPath())
	return res, nil
}

// savedFile is a host file's content before vesta-install changed it.
type savedFile struct {
	path    string
	data    []byte
	perm    fs.FileMode
	existed bool
}

func saveFile(root *hostfs.Root, p string) (savedFile, error) {
	b, err := root.ReadFile(p, maxConfigSize)
	if errors.Is(err, fs.ErrNotExist) {
		return savedFile{path: p}, nil
	}
	if err != nil {
		return savedFile{}, fmt.Errorf("save %s: %w", p, err)
	}
	perm := fs.FileMode(0o644)
	if info, err := root.Lstat(p); err == nil {
		perm = info.Mode.Perm()
	}
	return savedFile{path: p, data: b, perm: perm, existed: true}, nil
}

func (s savedFile) restore(root *hostfs.Root) error {
	if !s.existed {
		_, err := root.Remove(s.path)
		return err
	}
	_, err := root.WriteFile(s.path, s.data, s.perm)
	return err
}

// rollback restores the containerd config after containerd failed to come
// back with vesta's change, and restarts it once more on the old config.
func rollback(ctx context.Context, o *Options, plan *ContainerdPlan, saved []savedFile, cause error) error {
	o.Log.Error("containerd did not come back with the vesta drop-in; restoring the previous config", "err", cause)
	for _, s := range saved {
		if err := s.restore(o.Root); err != nil {
			return fmt.Errorf("restart containerd: %w; restoring %s also failed: %w", cause, s.path, err)
		}
	}
	if _, err := o.Restarter.Restart(ctx, plan.Units); err != nil {
		return fmt.Errorf("restart containerd: %w; previous config restored, but restarting on it failed too: %w", cause, err)
	}
	return fmt.Errorf("restart containerd with the vesta drop-in: %w (previous config restored and containerd restarted)", cause)
}

// writeRuntimeConfig writes the config and config.d into vdir and removes
// config.d entries that are no longer generated (Kata merges every file
// there).
func writeRuntimeConfig(root *hostfs.Root, vdir string, g *GeneratedKataConfig) error {
	if _, err := root.WriteFile(vdir+"/"+runtimeConfigName, g.Config, 0o644); err != nil {
		return fmt.Errorf("write runtime config: %w", err)
	}
	dropDir := vdir + "/config.d"
	if err := root.MkdirAll(dropDir); err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, d := range g.DropIns {
		if strings.ContainsAny(d.Name, "/\x00") || d.Name == "." || d.Name == ".." {
			return fmt.Errorf("invalid drop-in name %q", d.Name)
		}
		keep[d.Name] = true
		if _, err := root.WriteFile(dropDir+"/"+d.Name, d.Data, 0o644); err != nil {
			return fmt.Errorf("write drop-in: %w", err)
		}
	}
	names, err := root.ReadDir(dropDir)
	if err != nil {
		return err
	}
	for _, n := range names {
		if !keep[n] {
			if _, err := root.Remove(dropDir + "/" + n); err != nil {
				return fmt.Errorf("remove stale drop-in: %w", err)
			}
		}
	}
	return nil
}

// ErrInUse is returned by Uninstall while pods still use the handler.
var ErrInUse = errors.New("vesta runtime is in use")

// Uninstall reverses Install. It refuses while pods on the node use the
// vesta handler, and removes the node label first so nothing new is
// scheduled while it runs.
func Uninstall(ctx context.Context, o Options) error {
	if err := o.defaults(); err != nil {
		return err
	}
	log := o.Log
	pods, err := o.Kube.PodsUsingHandler(ctx, o.NodeName, o.Handler)
	if err != nil {
		return err
	}
	if len(pods) > 0 {
		return fmt.Errorf("%w by %d pod(s) on %s: %s", ErrInUse, len(pods), o.NodeName, strings.Join(first(pods, 10), ", "))
	}
	if err := o.Kube.SetLabel(ctx, o.NodeName, GuestReadyLabel, ""); err != nil {
		return err
	}
	// A pod scheduled before the label went away may have arrived since.
	if pods, err = o.Kube.PodsUsingHandler(ctx, o.NodeName, o.Handler); err != nil || len(pods) > 0 {
		if cur, rerr := o.Root.Readlink(o.currentLink()); rerr == nil && ValidVersion(cur) {
			if lerr := o.Kube.SetLabel(ctx, o.NodeName, GuestReadyLabel, cur); lerr != nil {
				log.Warn("could not restore guest-ready label", "err", lerr)
			}
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: pods appeared during uninstall: %s", ErrInUse, strings.Join(first(pods, 10), ", "))
	}

	changed := false
	for _, p := range []string{containerdConfD + "/" + dropInFile, vestaImportDropIn,
		fmt.Sprintf(rancherDirFmt, FlavorK3s) + "/" + k3sDropInDir + "/" + dropInFile,
		fmt.Sprintf(rancherDirFmt, FlavorRKE2) + "/" + k3sDropInDir + "/" + dropInFile} {
		removed, err := o.Root.Remove(p)
		if err != nil {
			return fmt.Errorf("remove containerd drop-in: %w", err)
		}
		changed = changed || removed
	}
	if ok, err := o.Root.Exists(containerdConfig); err != nil {
		return err
	} else if ok {
		imp, err := RemoveImport(o.Root, containerdConfig, vestaImportDropIn)
		if err != nil {
			return fmt.Errorf("containerd imports: %w", err)
		}
		changed = changed || imp
	}
	if changed {
		units := []string{"containerd.service", "k3s.service", "k3s-agent.service", "rke2-server.service", "rke2-agent.service"}
		if _, err := o.Restarter.Restart(ctx, units); err != nil {
			return fmt.Errorf("restart containerd: %w", err)
		}
	}
	if err := o.Root.RemoveAll(o.kataDir()); err != nil {
		return fmt.Errorf("remove guest assets: %w", err)
	}
	if err := o.Root.RemoveAll(o.VestaPrefix + "/containerd"); err != nil {
		return fmt.Errorf("remove containerd drop-in dir: %w", err)
	}
	log.Info("vesta runtime uninstalled", "node", o.NodeName)
	return nil
}

func first(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], "...")
	}
	return s
}
