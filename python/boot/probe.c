/* Test-only executable at the fixed interpreter path. Never ship in a guest. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <unistd.h>
extern char **environ;
#define CHECK(condition, code) do { if (!(condition)) return code; } while (0)
int main(int argc, char **argv) {
    CHECK(argc == 5 && !strcmp(argv[1], "-I") && !strcmp(argv[2], "-B") &&
          !strcmp(argv[3], "-m") && !strcmp(argv[4], "wcm.guest_broker"), 10);
    CHECK(getpid() == 1 && getuid() == 10001 && geteuid() == 10001 &&
          getgid() == 10001 && getgroups(0, NULL) == 0, 11);
    CHECK(environ[0] && !strcmp(environ[0], "LANG=C.UTF-8") && !environ[1], 12);
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, 13);
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2] = {{0}};
    CHECK(syscall(SYS_capget, &header, caps) == 0, 14);
    CHECK(!(caps[0].effective | caps[0].permitted | caps[0].inheritable |
            caps[1].effective | caps[1].permitted | caps[1].inheritable), 15);
    for (int i = 0; i <= CAP_LAST_CAP; ++i) CHECK(prctl(PR_CAPBSET_READ, i) == 0, 16);
    struct rlimit core;
    CHECK(getrlimit(RLIMIT_CORE, &core) == 0 && core.rlim_cur == 0 && core.rlim_max == 0, 17);
    for (int i = 0; i < 3; ++i) {
        struct stat fd;
        CHECK(fstat(i, &fd) == 0 && S_ISCHR(fd.st_mode) && fd.st_rdev == makedev(1, 3), 18);
    }
    CHECK(fcntl(3, F_GETFD) == -1 && errno == EBADF, 19);
    const char *mounts[] = {"/", "/run", "/dev"};
    for (unsigned int i = 0; i < 3; ++i) {
        struct statvfs fs;
        CHECK(statvfs(mounts[i], &fs) == 0 && (fs.f_flag & ST_RDONLY), 20);
    }
    CHECK(open("/usr/local/bin/python3", O_WRONLY) == -1 && (errno == EROFS || errno == EACCES), 21);
    CHECK(open("/run/config.json", O_WRONLY) == -1 && (errno == EROFS || errno == EACCES), 22);
    CHECK(setuid(0) == -1 && errno == EPERM, 23);
    CHECK(mount(NULL, "/", NULL, MS_REMOUNT, NULL) == -1 && errno == EPERM, 24);
    CHECK(access("/sys", F_OK) == -1 && access("/proc", F_OK) == -1 &&
          access("/outside", F_OK) == -1, 25);
    int config = open("/run/config.json", O_RDONLY);
    char buf[8] = {0};
    CHECK(config >= 0 && read(config, buf, 8) == 2 && !strcmp(buf, "{}"), 26);
    return 0;
}
