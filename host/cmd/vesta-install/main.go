// SPDX-License-Identifier: Apache-2.0

// Command vesta-install installs or removes the kata-qemu-vesta runtime on
// the node it runs on. It runs as the vesta-agent DaemonSet's init container
// (install) and from a pre-delete hook (uninstall).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path"
	"syscall"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dbcrit/vesta/host/internal/hostfs"
	"github.com/dbcrit/vesta/host/internal/install"
)

var version = "0.0.0-dev"

const usage = `Usage: vesta-install [install|uninstall] [flags]

install     check Kata, install the vesta guest kernel/image and runtime
            config, register the containerd handler, label the node
uninstall   reverse install; refused while pods use the vesta handler

Flags:
`

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		log.Error("vesta-install failed", "err", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger) error {
	cmd := "install"
	if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("vesta-install", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	hostRoot := fs.String("host-root", "/host", "where the node's root filesystem is mounted")
	assetsDir := fs.String("assets-dir", "/usr/share/vesta/guest", "directory with vmlinux-vesta, vesta-guest.img, SHA256SUMS and VERSION")
	guestVersion := fs.String("guest-version", "", "guest image version (default: assets-dir/VERSION)")
	nodeName := fs.String("node-name", os.Getenv("NODE_NAME"), "this node's name (default $NODE_NAME)")
	handler := fs.String("handler", install.DefaultHandler, "runtime handler to register")
	kataPrefix := fs.String("kata-prefix", install.DefaultKataPrefix, "Kata installation prefix on the node")
	vestaPrefix := fs.String("vesta-prefix", install.DefaultVestaPrefix, "vesta installation prefix on the node")
	restart := fs.String("restart", "systemd", "how to restart containerd after a config change: systemd or none")
	sdSocket := fs.String("systemd-socket", "", "systemd private socket (default <host-root>/run/systemd/private)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig for out-of-cluster use (default: in-cluster config)")
	nriValidator := fs.Bool("nri-default-validator", true, "enable containerd's NRI default validator in the drop-in, so the required-plugins pod annotation can make vesta mandatory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected arguments %v", fs.Args())
	}

	root, err := hostfs.New(*hostRoot)
	if err != nil {
		return err
	}
	var restarter install.Restarter
	switch *restart {
	case "systemd":
		sock := *sdSocket
		if sock == "" {
			sock = path.Join(*hostRoot, "run/systemd/private")
		}
		restarter = install.SystemdRestarter{Socket: sock}
	case "none":
		restarter = install.NoRestart{}
	default:
		return fmt.Errorf("-restart %q: want systemd or none", *restart)
	}
	kube, err := kubeClient(*kubeconfig)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := install.Options{
		Root: root, NodeName: *nodeName, Handler: *handler,
		KataPrefix: *kataPrefix, VestaPrefix: *vestaPrefix,
		Restarter: restarter, Kube: install.KubeAPI{Client: kube},
		Log:          log.With("node", *nodeName, "installer", version),
		NRIValidator: *nriValidator,
	}
	if cmd == "uninstall" {
		return install.Uninstall(ctx, opts)
	}
	opts.Assets, err = install.LoadAssets(*assetsDir, *guestVersion)
	if err != nil {
		return err
	}
	res, err := install.Install(ctx, opts)
	if err != nil {
		return err
	}
	log.Info("done", "guest_version", res.Version, "kata", res.KataVersion, "flavor", res.Flavor,
		"assets_changed", res.AssetsChanged, "containerd_changed", res.ContainerdChange, "restarted", res.RestartedUnit)
	return nil
}

func kubeClient(kubeconfig string) (kubernetes.Interface, error) {
	var cfg *rest.Config
	var err error
	if kubeconfig != "" {
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("kubernetes client config: %w", err)
	}
	cfg.UserAgent = "vesta-install/" + version
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("kubernetes client: %w", err)
	}
	return cs, nil
}
