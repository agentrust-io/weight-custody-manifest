/* Provisional Linux x86-64 PID 1. No shell, external disk, module loader or
 * fallback. Build: cc -static -O2 -Wall -Wextra -Werror init.c -o init
 * Hardware launch coverage and kernel/firmware review remain separate gates.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define MAX_CONFIG (1024 * 1024)
#define BROKER_UID 10001

static void fail(void) { _exit(111); } /* PID 1 exit stops the guest. */
static void need(int result) { if (result < 0) fail(); }

static void runtime_mounts(int config_fd, dev_t report_device) {
    need(mount("/runtime", "/runtime", NULL, MS_BIND, NULL));
    need(mount("tmpfs", "/runtime/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
               "size=2m,mode=0755"));
    int output = open("/runtime/run/config.json", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444);
    need(output);
    char data[4096];
    size_t total = 0;
    for (;;) {
        ssize_t count = read(config_fd, data, sizeof(data));
        if (count < 0) fail();
        if (count == 0) break;
        total += (size_t)count;
        if (total > MAX_CONFIG) fail();
        ssize_t done = 0;
        while (done < count) {
            ssize_t written = write(output, data + done, (size_t)(count - done));
            if (written <= 0) fail();
            done += written;
        }
    }
    if (total == 0) fail();
    need(close(output));
    need(close(config_fd));
    need(mount(NULL, "/runtime/run", NULL,
               MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL));
    need(mount("tmpfs", "/runtime/dev", "tmpfs", MS_NOSUID | MS_NOEXEC,
               "size=64k,mode=0755"));
    need(mknod("/runtime/dev/null", S_IFCHR | 0666, makedev(1, 3)));
    need(mknod("/runtime/dev/urandom", S_IFCHR | 0444, makedev(1, 9)));
    need(mknod("/runtime/dev/sev-guest", S_IFCHR | 0400, report_device));
    need(chown("/runtime/dev/sev-guest", BROKER_UID, BROKER_UID));
    need(mount(NULL, "/runtime/dev", NULL, MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOEXEC, NULL));
    need(mount(NULL, "/runtime", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV, NULL));
}

static void enter_runtime(void) {
    struct rlimit core = {0, 0};
    need(setrlimit(RLIMIT_CORE, &core));
    need(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    need(prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0));
    need(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0));
    for (int cap = 0; ; ++cap) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
            if (errno == EINVAL) break;
            fail();
        }
    }
    need(chdir("/runtime"));
    need(chroot("."));
    need(chdir("/"));
    need(setgroups(0, NULL));
    need(setresgid(BROKER_UID, BROKER_UID, BROKER_UID));
    need(setresuid(BROKER_UID, BROKER_UID, BROKER_UID));
    need(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0));
    /* Discard even unexpected inherited descriptors and host environment. */
    need((int)syscall(SYS_close_range, 0U, ~0U, 0));
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd != 0) fail();
    need(dup2(null_fd, 1));
    need(dup2(null_fd, 2));
    char *const argv[] = {"/usr/local/bin/python3", "-I", "-B", "-m", "wcm.guest_broker", NULL};
    char *const env[] = {"LANG=C.UTF-8", NULL};
    execve(argv[0], argv, env);
    fail();
}

int main(void) {
    if (getpid() != 1 || getuid() != 0) fail();
    umask(0);
    need(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    need(mount("sysfs", "/sys", "sysfs", MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL));
    need(mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL));
    struct stat device;
    need(stat("/dev/sev-guest", &device));
    if (!S_ISCHR(device.st_mode)) fail();
    int config = open("/sys/firmware/qemu_fw_cfg/by_name/opt/wcm/config/raw", O_RDONLY | O_CLOEXEC);
    need(config);
    runtime_mounts(config, device.st_rdev);
    enter_runtime();
    return 111;
}
