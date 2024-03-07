package commands

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	"github.com/STARRY-S/known-hosts-cleaner/pkg/utils"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func Execute(args []string) error {
	mainCmd := newMainCmd()
	mainCmd.cmd.SetArgs(args)
	_, err := mainCmd.cmd.ExecuteC()
	return err
}

type mainOpts struct {
	debug          bool
	ignalPrivate   bool
	ipOnly         bool
	knownHostsFile string
}

type mainCmd struct {
	cmd  *cobra.Command
	opts *mainOpts
}

func newMainCmd() *mainCmd {
	opts := &mainOpts{}
	cc := &mainCmd{
		opts: opts,
		cmd: &cobra.Command{
			Use:  "sshcleaner",
			Long: "Clean unknown IP hosts in '~/.ssh/known_hosts'",
		},
	}
	cc.cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return cc.clean()
	}

	cc.cmd.SilenceUsage = true
	cc.cmd.SilenceErrors = true
	cc.cmd.Version = utils.Version

	flags := cc.cmd.PersistentFlags()
	flags.BoolVarP(&opts.debug, "debug", "", false, "enable the debug output")
	flags.BoolVarP(&opts.ignalPrivate, "ignore-local", "", true,
		"do not delete IP address in '10.0.0/8', '172.16.0.0/12', '192.168.0.0/16' CIDR")
	flags.BoolVarP(&opts.ipOnly, "ip-only", "", true, "clean IP address only")
	flags.StringVarP(&opts.knownHostsFile, "file", "f",
		path.Join(os.Getenv("HOME"), ".ssh", "known_hosts"), "known_hosts file path")

	return cc
}

func (cc *mainCmd) clean() error {
	if cc.opts.knownHostsFile == "" {
		return fmt.Errorf("known_hosts not specified")
	}
	if cc.opts.debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	f, err := os.Open(cc.opts.knownHostsFile)
	if err != nil {
		return fmt.Errorf("failed to open %q: %w", cc.opts.knownHostsFile, err)
	}
	sc := bufio.NewScanner(f)
	sc.Split(bufio.ScanLines)
	knownHostsNew := []string{}
	removeHosts := map[string]bool{}
	for sc.Scan() {
		l := sc.Text()
		spec := strings.Split(l, " ")
		if len(spec) < 3 {
			logrus.Warnf("ignore invalid line %q", l)
			continue
		}
		host := getHost(spec[0])
		logrus.Debugf("handle host: %v", host)
		// Ignore non-ip address (domain) host
		if !isIPAddress(host) && cc.opts.ipOnly {
			logrus.Debugf("reserve non-ip address line %q", l)
			knownHostsNew = append(knownHostsNew, l)
			continue
		}
		// Ignore private IP addresses
		if isPrivateAddress(host) && cc.opts.ignalPrivate {
			logrus.Debugf("reserve private addr line %q", l)
			knownHostsNew = append(knownHostsNew, l)
			continue
		}
		removeHosts[spec[0]] = true
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close %q: %w",
			cc.opts.knownHostsFile, err)
	}
	if cc.opts.debug {
		logrus.Debugf("output: ")
		logrus.Debugf("---------------------------------")
		fmt.Printf("%v\n", strings.Join(knownHostsNew, "\n"))
		logrus.Debugf("---------------------------------")
		logrus.Debugf("debug enabled, will not write changes to %q",
			cc.opts.knownHostsFile)
		return nil
	}

	if len(removeHosts) > 0 {
		logrus.Infof("Following host(s) will be deleted in the known_hosts file:")
		for k := range removeHosts {
			fmt.Printf("%v\n", k)
		}
		fmt.Printf("Continue? [y/N] ")
		var s string
		if _, err := fmt.Scanf("%s", &s); err != nil {
			return fmt.Errorf("abort")
		}
		if len(s) == 0 || s[0] != 'y' && s[0] != 'Y' {
			return fmt.Errorf("abort")
		}
	} else {
		logrus.Infof("The %q is already cleaned up.", cc.opts.knownHostsFile)
		return nil
	}

	f, err = os.OpenFile(cc.opts.knownHostsFile, os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to re-create %q: %w",
			cc.opts.knownHostsFile, err)
	}
	defer f.Close()
	if _, err := f.WriteString(strings.Join(knownHostsNew, "\n")); err != nil {
		return fmt.Errorf("failed to write %q: %w",
			cc.opts.knownHostsFile, err)
	}
	logrus.Infof("Finished clean-up the %q file.", cc.opts.knownHostsFile)

	return nil
}

func getHost(s string) string {
	s = strings.ReplaceAll(s, "[", "")
	s = strings.ReplaceAll(s, "]", "")
	s1, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return s1
}

func isIPAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil
}

func isPrivateAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsPrivate()
}
