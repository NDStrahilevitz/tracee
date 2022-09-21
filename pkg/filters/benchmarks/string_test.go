package benchmarks

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/aquasecurity/tracee/pkg/filters"
	"github.com/stretchr/testify/require"
)

func matchFilter(filters []string, argValStr string) bool {
	for _, f := range filters {
		prefixCheck := f[len(f)-1] == '*'
		if prefixCheck {
			f = f[0 : len(f)-1]
		}
		suffixCheck := f[0] == '*'
		if suffixCheck {
			f = f[1:]
		}
		if argValStr == f ||
			(prefixCheck && !suffixCheck && strings.HasPrefix(argValStr, f)) ||
			(suffixCheck && !prefixCheck && strings.HasSuffix(argValStr, f)) ||
			(prefixCheck && suffixCheck && strings.Contains(argValStr, f)) {
			return true
		}
	}
	return false
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

// generate random strings with 50% to match a prefix
func randStringRunes(n int, filters []string) string {
	symbols := []string{}
	for _, filter := range filters {
		symbol := strings.TrimSuffix(filter, "*")
		symbol = strings.TrimPrefix(symbol, "*")
		symbols = append(symbols, symbol)
	}
	b := make([]rune, n)
	c := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
		c[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	num := rand.Intn(101)
	str := string(b)
	str2 := string(c)
	if num < 25 {
		return str
	}
	if num < 50 {
		return str + selectRandomElement(symbols) + str2
	}
	if num < 75 {
		return str + selectRandomElement(symbols)
	}

	return selectRandomElement(symbols) + str
}

func selectRandomElement(list []string) string {
	return list[rand.Intn(len(list))]
}

var filterVals = []string{
	"*/notify_on_release", "*/core_pattern", "/etc/selinux*", "/selinux*", "/etc/sysconfig/selinux*", "*.bash_profile", "*.bashrc", "*.bash_logout", "*.bash_login",
	"/etc/profile.d*", "/etc/profile*", "/etc/bashrc*", "*.profile", "/home/*", "/root/*", "*kubeadm-kubelet-config.yaml", "*kubelet.conf", "*/kubelet/config.yaml",
	"*kubelet-config.yaml", "/proc/kcore", "*/sched_debug", "flanneld", "kube-proxy", "prometheus", "md5sum", "*/etc/shadow", "*/etc/profile", "*/etc/master.passwd",
	"*/etc/shells", "*/etc/netsvc.conf", "/etc/rc.local", "/etc/init.d/rc.local", "/etc/rc1.d*", "/etc/rc2.d*", "/etc/rc3.d*", "/etc/rc4.d*", "/etc/rc5.d*",
	"/etc/rc6.d*", "/etc/rcs.d*", "/etc/init.d*", "/etc/rc.d/rc.local*", "/etc/rc.d/init.d*", "/etc/rc.d*", "/proc/sys/kernel/randomize_va_space", "/etc/crontab",
	"/etc/anacrontab", "/etc/cron.deny", "/etc/cron.allow", "/etc/cron.hourly*", "/etc/cron.daily*", "/etc/cron.weekly*", "/etc/cron.monthly*", "/etc/cron.d*",
	"/var/spool/cron/crontabs*", "var/spool/anacron*", "/etc/crontab", "/var/spool/cron/crontabs", "/etc/anacrontab", "var/spool/anacron", "/etc/cron.deny",
	"/etc/cron.allow", "/var/spool/cron/crontabs", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly", "/etc/cron.d", "sshd", "ssh",
	"containerd", "*/python*", "*/dist-packages/*", "*authorized_keys", "*identity.pub", "*id_rsa.pub", "*id_rsa", "*ssh_config", "*id_dsa.pub", "*/etc/ld.so.preload",
	"*.dockerignore", "/proc/sys/kernel/sysrq", "/proc/sysrq-trigger", "containerd", "*git/credentials/*", "*config/google-chrome/default/login data*", "*/.ssh/*",
	"*.npmrpc", "*.git-credentials", "*key4.db", "*logins.json", "*authorized_keys", "*docker.sock", "*/release_agent", "kube-apiserver", "kubelet", "kube-controller",
	"etcd", "/etc/kubernetes/pki/*", "/etc/shadow", "*nr_hugepages", "*free_hugepages", "*/sys/module/msr/parameters/allow_writes", "/etc/sudoers", "/private/etc/sudoers",
	"/etc/sudoers.d/*", "/private/etc/sudoers.d/*", "/sys/kernel/debug/kprobes/enabled", "*secrets/kubernetes.io/serviceaccount*", "*config", "*mem",
}

func BenchmarkStringFilter(b *testing.B) {
	filter := filters.NewStringFilter()
	err := filter.Parse(fmt.Sprintf("=%s", strings.Join(filterVals, ",")))
	require.NoError(b, err)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		filter.Filter(randStringRunes(6, filterVals))
	}
}

func BenchmarkMatchFilter(b *testing.B) {
	for n := 0; n < b.N; n++ {
		matchFilter(filterVals, randStringRunes(6, filterVals))
	}
}
