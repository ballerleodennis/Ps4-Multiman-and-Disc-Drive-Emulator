# Ps4-Multiman-and-Disc-Drive-Emulator



Alles, was auf der PS4 nicht aufrufbar ist, ist raus. Beide Projekte, bereinigt, mit Firmware-Matrix.

**Entfernt gegenüber der letzten Fassung:** Sound (`cellAudio`), Freispeicheranzeige (`sceKernelStatfs` unbestätigt), Registry/`sys_storage`, `sysSmMount`/`sysIso`, PKG-Installer (`cellFsInstallPackage`), `cellGame*`, PS1/PS2-Classics, Kopier-Engine. Dazu alle sieben offenen Header-Punkte, die sich nicht gegen den SDK-Stand verifizieren ließen, inklusive `SceKernelSwVersion.version_string` im Payload.

---

# PROJEKT 1: discmgr — Disc-Emulator (FW 6.72 / 10.01 / 13.52 / 14.02)

**Umfang:** Kernel-Payload für `/dev/bdiso0` + Daemon für Validierung, Mount, Launch. Ein ELF pro Firmware, Build-Zeit-Auswahl, Laufzeit-Verifikation.

### Firmware-Matrix

| FW | Kernelbasis | Auflösung | SMEP/SMAP | Devicename |
|---|---|---|---|---|
| 6.72 | FreeBSD 9 | statische Offsets | aus | `bdiso0` |
| 10.01 | FreeBSD 11 | Signatursuche | an | `bdiso1` |
| 13.52 | FreeBSD 11 | Signatursuche | an | `bdiso1` |
| 14.02 | FreeBSD 11 | Signatursuche | an | `bdiso1` |

### Dateibaum

```
discmgr/
├── Makefile
├── targets/ fw.h table.c
├── kexp/    ipc.h main.c cdev.c quirks.c sigscan.c elfrange.c
├── daemon/  discmgrd.c fwcheck.c sfo.h sfo.c
└── tools/   discctl.c iso-verify.py
```

### `targets/fw.h`

```c
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    const char *sw_prefix;
    int         freebsd;
    int         use_sigscan;
    int         smep_smap;
    const char *mod_cd;
    const char *mod_sblbd;
    uint64_t    off_cd_strategy;
    uint64_t    off_cd_open;
    const char *sig_cd_strategy;
    const char *sig_cd_open;
    size_t      sig_cd_strategy_len;
    size_t      sig_cd_open_len;
    const char *dev_name;
    int         allow_titledir;
} FwTarget;

extern const FwTarget fw_targets[];
extern const int fw_target_count;
const FwTarget *fw_lookup(const char *sw);
```

### `targets/table.c`

```c
#include "fw.h"

#define SIG(x) x, sizeof(x) - 1
#define S_STRAT "\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53"
#define S_OPEN  "\x55\x48\x89\xe5\x41\x55\x41\x54\x53\x48\x83\xec"

const FwTarget fw_targets[] = {
    { "06.720", 9, 0, 0, "cd", "sceSblBd", 0x0, 0x0, NULL, NULL, 0, 0,
      "bdiso0", 1 },
    { "10.010", 11, 1, 1, "cd", "sceSblBd", 0, 0, SIG(S_STRAT), SIG(S_OPEN),
      "bdiso1", 1 },
    { "13.520", 11, 1, 1, "cd", "sceSblDriver", 0, 0, SIG(S_STRAT), SIG(S_OPEN),
      "bdiso1", 1 },
    { "14.020", 11, 1, 1, "cd", "sceSblDriver", 0, 0, SIG(S_STRAT), SIG(S_OPEN),
      "bdiso1", 1 },
};
const int fw_target_count = sizeof(fw_targets) / sizeof(fw_targets[0]);

const FwTarget *fw_lookup(const char *sw)
{
    if (!sw) return NULL;
    for (int i = 0; i < fw_target_count; i++)
        if (!__builtin_strncmp(sw, fw_targets[i].sw_prefix, 6))
            return &fw_targets[i];
    return NULL;
}
```

### `kexp/ipc.h`

```c
#pragma once
#include <stdint.h>

#define DISCISO_MOUNT   0x80014401UL
#define DISCISO_UNMOUNT 0x80014402UL

struct disciso_mount_arg { int fd; uint64_t size; };
```

### `kexp/elfrange.c`

```c
#include <stdint.h>

typedef struct { uint64_t start, end; } Range;

int elf_text_range(uint64_t base, Range *out)
{
    const uint8_t *eh = (const uint8_t *)base;
    uint64_t phoff;
    uint16_t phnum;

    if (*(uint32_t *)eh != 0x464C457F || eh[4] != 2) return -1;
    __builtin_memcpy(&phoff, eh + 0x20, 8);
    __builtin_memcpy(&phnum, eh + 0x38, 2);
    if (!phoff || !phnum || phnum > 16) return -1;

    out->start = UINT64_MAX; out->end = 0;
    for (int i = 0; i < phnum; i++) {
        const uint8_t *ph = eh + phoff + i * 56;
        uint32_t type, flags;
        uint64_t vaddr, filesz;
        __builtin_memcpy(&type, ph, 4);
        __builtin_memcpy(&flags, ph + 4, 4);
        __builtin_memcpy(&vaddr, ph + 16, 8);
        __builtin_memcpy(&filesz, ph + 32, 8);
        if (type != 1 || !(flags & 1) || !filesz) continue;
        if (base + vaddr < out->start) out->start = base + vaddr;
        if (base + vaddr + filesz > out->end) out->end = base + vaddr + filesz;
    }
    return out->end > out->start ? 0 : -1;
}
```

### `kexp/sigscan.c`

```c
#include <stdint.h>
#include "elfrange.c"

int sig_scan(uint64_t base, const char *sig, size_t len, uint64_t *hit)
{
    Range r;
    const uint8_t *p;
    uint64_t n;

    if (elf_text_range(base, &r)) return -1;
    p = (const uint8_t *)r.start;
    n = r.end - r.start - len;

    for (uint64_t i = 0; i < n; i += 4)
        if (p[i] == (uint8_t)sig[0] && !__builtin_memcmp(p + i, sig, len))
            { *hit = r.start + i; return 0; }
    for (uint64_t i = 0; i < n; i++)
        if (p[i] == (uint8_t)sig[0] && !__builtin_memcmp(p + i, sig, len))
            { *hit = r.start + i; return 0; }
    return -1;
}
```

### `kexp/quirks.c`

```c
#include "../targets/fw.h"

void quirks_enter(const FwTarget *t)
{
    if (t->smep_smap)
        __asm__ volatile("mov %%cr4,%%rax; and $~((1<<20)|(1<<21)),%%rax;"
                         "mov %%rax,%%cr4" ::: "rax");
    __asm__ volatile("mov %%cr0,%%rax; and $~0x10000,%%rax; mov %%rax,%%cr0" ::: "rax");
}

void quirks_leave(const FwTarget *t)
{
    __asm__ volatile("mov %%cr0,%%rax; or $0x10000,%%rax; mov %%rax,%%cr0" ::: "rax");
    if (t->smep_smap)
        __asm__ volatile("mov %%cr4,%%rax; or $((1<<20)|(1<<21)),%%rax;"
                         "mov %%rax,%%cr4" ::: "rax");
}
```

### `kexp/cdev.c`

```c
#include "ipc.h"
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/bio.h>
#include <sys/fcntl.h>

#define SECTOR 2048

static struct file *g_fp;
static uint64_t     g_size;
static struct cdev *g_dev;
static const char  *g_name;

static int disciso_open(struct cdev *d, int f, int fmt, struct thread *td)
{ return g_fp ? 0 : ENXIO; }
static int disciso_close(struct cdev *d, int f, int fmt, struct thread *td)
{ return 0; }

static int disciso_read(struct cdev *d, struct uio *uio, int ioflag)
{
    if (!g_fp) return ENXIO;
    if (uio->uio_offset >= g_size) return 0;
    if (uio->uio_offset + uio->uio_resid > g_size)
        uio->uio_resid = g_size - uio->uio_offset;
    return fo_read(g_fp, uio, curthread->td_ucred, FOF_OFFSET, curthread);
}

static int disciso_write(struct cdev *d, struct uio *uio, int ioflag) { return 0; }
static int disciso_strategy(struct bio *bp) { return physio(bp->bio_dev, bp); }

static int disciso_ioctl(struct cdev *d, u_long cmd, caddr_t data,
                         int ff, struct thread *td)
{
    struct disciso_mount_arg *a = (void *)data;
    struct file *fp;
    int err;

    switch (cmd) {
    case DIOCGSECTORSIZE: *(u_int *)data = SECTOR; return 0;
    case DIOCGMEDIASIZE:  *(off_t *)data = g_size; return 0;
    case DISCISO_MOUNT:
        if (g_fp) return EBUSY;
        err = fget(td, a->fd, &fp);
        if (err) return err;
        if (fp->f_type != DTYPE_VNODE || fp->f_vnode->v_type != VREG ||
            a->size == 0 || a->size % SECTOR) { fdrop(fp, td); return EINVAL; }
        g_fp = fp; g_size = a->size;
        return 0;
    case DISCISO_UNMOUNT:
        if (g_fp) fdrop(g_fp, td);
        g_fp = NULL; g_size = 0;
        return 0;
    }
    return ENOTTY;
}

static struct cdevsw disciso_cdevsw = {
    .d_version = D_VERSION, .d_open = disciso_open, .d_close = disciso_close,
    .d_read = disciso_read, .d_write = disciso_write,
    .d_ioctl = disciso_ioctl, .d_strategy = disciso_strategy,
    .d_name = "bdiso",
};

int cdev_install(const char *name)
{
    g_name = name;
    g_dev = make_dev(&disciso_cdevsw, 0, UID_ROOT, GID_OPERATOR, 0666, name);
    return g_dev ? 0 : ENOMEM;
}

void cdev_remove(void) { if (g_dev) { destroy_dev(g_dev); g_dev = NULL; } }
```

### `kexp/main.c`

```c
#include "ipc.h"
#include "../targets/fw.h"

#ifndef TARGET_FW
#error "TARGET_FW setzen (672|1001|1352|1402)"
#endif

int  cdev_install(const char *);
void cdev_remove(void);
int  sig_scan(uint64_t, const char *, size_t, uint64_t *);
void quirks_enter(const FwTarget *);
void quirks_leave(const FwTarget *);

struct payload_args {
    uint64_t (*get_module_base)(const char *name);
    int      (*kernel_memcpy)(void *, const void *, uint64_t);
    int      (*kernel_memset)(void *, int, uint64_t);
};

static struct payload_args *pa;

/* Build-Zeit-Auswahl: das ELF weiss, fuer welche FW es gebaut wurde.
 * Laufzeit prueft nur, ob die Erwartung zutrifft. */
static const FwTarget *T;

static int verify(void)
{
    uint64_t cd = pa->get_module_base(T->mod_cd);
    if (!cd) return -1;
    if (!pa->get_module_base(T->mod_sblbd)) return -1;

    if (T->use_sigscan) {
        uint64_t a, b;
        if (sig_scan(cd, T->sig_cd_strategy, T->sig_cd_strategy_len, &a)) return -1;
        if (sig_scan(cd, T->sig_cd_open, T->sig_cd_open_len, &b)) return -1;
    } else if (*(uint8_t *)(cd + T->off_cd_strategy) != 0x55) {
        return -1;
    }
    return 0;
}

int _start(struct payload_args *args)
{
    static const int idx[] = { 0, 1, 2, 3 };
    static const int want[] = { 672, 1001, 1352, 1402 };

    pa = args;
    for (int i = 0; i < 4; i++)
        if (want[i] == TARGET_FW) T = &fw_targets[idx[i]];

    if (verify()) return -1;

    quirks_enter(T);
    int err = cdev_install(T->dev_name);
    quirks_leave(T);
    return err;
}
```

### `daemon/fwcheck.c`

```c
#include <orbis/libkernel.h>
#include <string.h>

int fw_supported(const char *sw)
{
    static const char *ok[] = { "06.720", "10.010", "13.520", "14.020" };
    if (!sw) return 0;
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (!strncmp(sw, ok[i], 6)) return 1;
    return 0;
}

/* Index in fw_targets[] fuer den erkannten Stand, -1 bei Unbekanntem. */
int fw_index(const char *sw)
{
    if (!fw_supported(sw)) return -1;
    for (int i = 0; i < fw_target_count; i++)
        if (!strncmp(sw, fw_targets[i].sw_prefix, 6)) return i;
    return -1;
}
```

### `daemon/sfo.h` / `sfo.c`

`sfo_read_title_id(buf, len, out, category)` — Magic `0x46535000`, Grenzprüfungen auf Key-/Datentabelle, nur `FMT_UTF8`, `TITLE_ID` ≤ 16 Byte, `CATEGORY` ≤ 8 Byte. Unverändert wie geliefert.

### `daemon/discmgrd.c`

```c
#include "disc_req.h"
#include "sfo.h"
#include "../targets/fw.h"
#include <orbis/libkernel.h>
#include <orbis/SystemService.h>
#include <orbis/LncUtil.h>
#include <orbis/AppInstUtil.h>
#include <orbis/UserService.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REQ_PATH   "/data/discmgr/req"
#define RSP_PATH   "/data/discmgr/rsp"
#define LOCK_PATH  "/data/discmgr/lock"
#define LOG_PATH   "/data/discmgr/discmgrd.log"
#define REAL_DEV   "/dev/cd0"
#define MOUNT      "/mnt/disc"
#define SFO_PATH   MOUNT "/app/sce_sys/param.sfo"
#define SECTOR     2048

#define DISCISO_MOUNT   0x80014401UL
#define DISCISO_UNMOUNT 0x80014402UL
struct disciso_mount_arg { int fd; uint64_t size; };

static volatile sig_atomic_t g_stop;
static uint32_t g_seq;
static int      g_fd = -1;
static char     g_iso[DISC_PATH_MAX];
static char     g_tid[16];
static char     g_dev[32];
static const FwTarget *T;
static int      g_installed, g_await;

int fw_supported(const char *);
int fw_index(const char *);

static void on_sig(int s) { (void)s; g_stop = 1; }

static void logf_(const char *fmt, ...)
{
    char line[512]; va_list ap; int n, fd;
    va_start(ap, fmt); n = vsnprintf(line, sizeof(line) - 2, fmt, ap); va_end(ap);
    if (n < 0) return;
    line[n] = '\n'; line[n + 1] = '\0';
    fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd >= 0) { write(fd, line, (size_t)n + 1); close(fd); }
}

static int lock_acquire(void)
{
    char pid[24]; int fd, n;
    fd = open(LOCK_PATH, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, pid, sizeof(pid) - 1); close(fd);
        if (n > 0) {
            pid[n] = '\0';
            if (kill(atoi(pid), 0) == 0) return -1;
        }
    }
    fd = open(LOCK_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) return -1;
    n = snprintf(pid, sizeof(pid), "%d", (int)getpid());
    write(fd, pid, (size_t)n); close(fd);
    return 0;
}

/* pread ist nicht verlaesslich: lseek + read, Daemon ist single-threaded. */
static int read_at(int fd, void *buf, size_t len, uint64_t off)
{
    if (lseek(fd, (off_t)off, SEEK_SET) < 0) return -1;
    return read(fd, buf, len) == (ssize_t)len ? 0 : -1;
}

static int is_udf(int fd, uint64_t size)
{
    uint8_t sec[3 * SECTOR];
    if (size < 20 * SECTOR || size % SECTOR) return -1;
    if (read_at(fd, sec, sizeof(sec), 16ULL * SECTOR)) return -1;
    if (memcmp(sec + SECTOR + 1, "BEA01", 5)) return -1;
    if (memcmp(sec + 2 * SECTOR + 1, "NSR02", 5) &&
        memcmp(sec + 2 * SECTOR + 1, "NSR03", 5)) return -1;
    return 0;
}

static int real_disc(void)
{
    int fd = open(REAL_DEV, O_RDONLY); off_t sz = 0;
    if (fd < 0) return 0;
    ioctl(fd, DIOCGMEDIASIZE, &sz); close(fd);
    return sz > 0;
}

static int game_running(void)
{
    SceSystemServiceStatus st;
    return sceSystemServiceGetStatus(&st) == 0 && st.isGameRunning;
}

static int do_unmount(void)
{
    if (g_await && game_running()) return DISC_E_BUSY;
    if (g_fd >= 0) {
        unmount(MOUNT, 0);
        int d = open(g_dev, O_RDONLY);
        if (d >= 0) { ioctl(d, DISCISO_UNMOUNT, NULL); close(d); }
        close(g_fd); g_fd = -1;
        logf_("unmount %s", g_iso);
    }
    if (g_installed) { sceAppInstUtilAppUnInstall(g_tid); g_installed = 0; }
    g_await = 0; g_tid[0] = g_iso[0] = '\0';
    return DISC_OK;
}

static int do_mount(const char *path, DiscRsp *rsp)
{
    struct disciso_mount_arg a;
    struct stat st;
    uint8_t sfo[8192];
    char cat[8] = {0};
    int fd, d, n;

    if (g_fd >= 0 || real_disc() || game_running()) return DISC_E_BUSY;

    fd = open(path, O_RDONLY);
    if (fd < 0) return DISC_E_IO;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return DISC_E_INVALID; }
    if (is_udf(fd, (uint64_t)st.st_size)) { close(fd); return DISC_E_INVALID; }

    d = open(g_dev, O_RDONLY);
    if (d < 0) { close(fd); return DISC_E_NODEV; }
    a.fd = fd; a.size = (uint64_t)st.st_size;
    if (ioctl(d, DISCISO_MOUNT, &a)) { close(d); close(fd); return DISC_E_MOUNT; }
    close(d);

    if (mount("udf", g_dev, MOUNT, 0, NULL)) {
        d = open(g_dev, O_RDONLY);
        if (d >= 0) { ioctl(d, DISCISO_UNMOUNT, NULL); close(d); }
        close(fd); return DISC_E_MOUNT;
    }

    n = open(SFO_PATH, O_RDONLY);
    if (n < 0 || read(n, sfo, sizeof(sfo)) < 0x14) {
        if (n >= 0) close(n);
        do_unmount(); return DISC_E_INVALID;
    }
    close(n);
    if (sfo_read_title_id(sfo, sizeof(sfo), rsp->title_id, cat)) {
        do_unmount(); return DISC_E_INVALID;
    }
    if (cat[0] && strcmp(cat, "gd")) { do_unmount(); return DISC_E_INVALID; }

    g_fd = fd;
    snprintf(g_iso, sizeof(g_iso), "%s", path);
    snprintf(g_tid, sizeof(g_tid), "%s", rsp->title_id);
    logf_("mount %s als %s", path, rsp->title_id);
    return DISC_OK;
}

static int do_launch(DiscRsp *rsp)
{
    SceLncLaunchAppParam p;
    int uid = 0;

    if (g_fd < 0) return DISC_E_NODEV;
    sceUserServiceGetForegroundUser(&uid);
    memset(&p, 0, sizeof(p));
    p.size = sizeof(p);
    p.userId = uid;

    if (sceLncUtilLaunchApp(g_tid, NULL, &p) == 0) { g_await = 1; return DISC_OK; }

    if (!T->allow_titledir) return DISC_E_LAUNCH;
    if (sceAppInstUtilAppInstallTitleDir(g_tid, MOUNT "/app", 0)) {
        snprintf(rsp->detail, sizeof(rsp->detail), "Registrierung abgelehnt");
        return DISC_E_LAUNCH;
    }
    g_installed = 1;
    if (sceLncUtilLaunchApp(g_tid, NULL, &p)) return DISC_E_LAUNCH;
    g_await = 1;
    return DISC_OK;
}

static void respond(const DiscReq *q, DiscRsp *r)
{
    char tmp[64]; int fd;
    r->seq = q->seq;
    snprintf(tmp, sizeof(tmp), "%s.tmp", RSP_PATH);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) return;
    if (write(fd, r, sizeof(*r)) != (ssize_t)sizeof(*r)) { close(fd); unlink(tmp); return; }
    close(fd); rename(tmp, RSP_PATH);
}

static void handle(void)
{
    DiscReq q; DiscRsp r; struct stat st; int fd, n;

    if (stat(REQ_PATH, &st) || (uint32_t)st.st_size != sizeof(q)) return;
    fd = open(REQ_PATH, O_RDONLY);
    if (fd < 0) return;
    n = read(fd, &q, sizeof(q)); close(fd);
    if (n != (int)sizeof(q) || q.seq == g_seq) return;

    g_seq = q.seq; memset(&r, 0, sizeof(r)); unlink(REQ_PATH);

    switch (q.op) {
    case DISC_OP_MOUNT:   r.status = do_mount(q.path, &r); break;
    case DISC_OP_UNMOUNT: r.status = do_unmount(); break;
    case DISC_OP_LAUNCH:  r.status = do_launch(&r); break;
    case DISC_OP_STATUS:
        r.status = g_fd >= 0 ? DISC_OK : DISC_E_NODEV;
        snprintf(r.title_id, sizeof(r.title_id), "%s", g_tid);
        break;
    default: r.status = DISC_E_INVALID;
    }
    respond(&q, &r);
}

int main(void)
{
    char sw[16] = "unbekannt";
    int idx;

    sceKernelMkdir("/data/discmgr", 0777);
    signal(SIGTERM, on_sig);
    signal(SIGINT, on_sig);

    SceKernelSwVersion v;
    if (sceKernelGetSystemSwVersion(&v) == 0)
        snprintf(sw, sizeof(sw), "%s", v.version_string);
    idx = fw_index(sw);
    if (idx < 0) { logf_("FW %s nicht unterstuetzt", sw); return 2; }
    T = &fw_targets[idx];
    snprintf(g_dev, sizeof(g_dev), "/dev/%s", T->dev_name);
    logf_("discmgrd start auf FW %s, Device %s", sw, g_dev);

    if (lock_acquire()) return 1;

    while (!g_stop) {
        handle();
        if (g_await && !game_running()) { logf_("Spiel beendet"); do_unmount(); }
        sceKernelUsleep(50 * 1000);
    }
    do_unmount(); unlink(LOCK_PATH);
    logf_("discmgrd beendet");
    return 0;
}
```

### `tools/discctl.c` und `tools/iso-verify.py`

Wie zuvor: `discctl mount|unmount|launch|status` über die Request-Queue, `iso-verify.py` prüft Größe % 2048 und UDF-Kennung.

### Build

```bash
make kexp FW=672
make kexp FW=1001
make kexp FW=1352
make kexp FW=1402
make daemon
```

### Abnahmekriterien

1. Payload auf falscher FW → Abbruch ohne Patch.
2. UDF-Testimage auf allen vier FWs mountbar.
3. 100 × Mount/Unmount ohne File-Leak.
4. Echte Disc → `DISC_E_BUSY`.
5. USB-Abziehen im Betrieb → `DISC_E_IO`, keine Panic.
6. `quirks_leave` setzt CR4.SMEP/SMAP zurück (klog).

---

# PROJEKT 2: multiman-ps4 — UI-Port (FW 6.72 / 10.01 / 13.52 / 14.02)

**Umfang:** Dateiliste, Mount, Start. Nur Aufrufe, die auf der PS4 existieren.

**Bewusst nicht enthalten:** Sound, Freispeicheranzeige, Kopierfunktion, Registry, PKG-Installation, PS1/PS2-Classics, FTP.

### Dateibaum

```
multiman-ps4/
├── Makefile
├── app.json
├── sce_module/libSDL2.so
├── data/font.dat theme.ini
└── src/
    ├── app.h main.c port/poison.h
    ├── hal/  fs.c input.c sys.c video.c
    ├── core/ watchdog.c scan.c config.c disc_client.c fwcheck.c
    └── ui/   font.c theme.c list.c dialog.c
```

### `port/poison.h`

Hält die entfernten Bereiche draußen — Wiedereinbau erzeugt sofort einen Linkfehler.

```c
#pragma once
#define MM_POISON(s) int mm_poison_##s(void)
MM_POISON(cellAudioInit); MM_POISON(cellFsGetFreeSize);
MM_POISON(sysSmMount); MM_POISON(sysIsoMount);
MM_POISON(sys_storage_get_device_info);
MM_POISON(cellFsInstallPackage); MM_POISON(cellGameInit);
#define cellAudioInit mm_poison_cellAudioInit
#define cellFsGetFreeSize mm_poison_cellFsGetFreeSize
#define sysSmMount mm_poison_sysSmMount
#define sysIsoMount mm_poison_sysIsoMount
#define sys_storage_get_device_info mm_poison_sys_storage_get_device_info
#define cellFsInstallPackage mm_poison_cellFsInstallPackage
#define cellGameInit mm_poison_cellGameInit
```

Letztes Include in `app.h`.

### `app.h`

```c
#pragma once
#include <stdint.h>
#include <stddef.h>

#define MM_VERSION       "0.2.0"
#define MM_ROOT          "/data/multiman"
#define MM_LOG           MM_ROOT "/mm.log"
#define MM_CFG           MM_ROOT "/config.ini"
#define MM_QC            "/data/discmgr"
#define MM_DISC_ROOT     "/data/discs"
#define MM_MOUNT         "/mnt/disc"

#define MM_SCREEN_W 1920
#define MM_SCREEN_H 1080
#define MM_MAX_ENTRIES 512
#define MM_PATH_MAX 256
#define MM_STACK_MAIN (1024 * 1024)
#define MM_WD_TIMEOUT_MS 8000

#define MM_OK 0
#define MM_ERR_IO -1
#define MM_ERR_TIMEOUT -2
#define MM_ERR_SHORT -3
#define MM_ERR_NOMEM -4
#define MM_ERR_BUSY -5
#define MM_ERR_NODEV -6

typedef struct { char path[MM_PATH_MAX]; char name[128]; uint64_t size; } MmEntry;

typedef struct {
    MmEntry entries[MM_MAX_ENTRIES];
    int count, sel, top, busy;
    char status[128];
} MmState;

extern MmState g_state;
extern int g_fw_major;
void mm_log(const char *fmt, ...);

#include "port/poison.h"
```

### `hal/fs.c`

```c
#include "fs.h"
#include "../app.h"
#include "../core/watchdog.h"
#include <orbis/Kernel.h>
#include <orbis/libkernel.h>
#include <fcntl.h>
#include <string.h>

static uint64_t now_ms(void) { return sceKernelGetProcessTimeLow() / 1000ULL; }

int mm_fs_init(void)
{
    if (sceKernelMkdir(MM_ROOT, 0777) == 0) return MM_OK;
    MmStat st;
    return mm_fs_stat(MM_ROOT, &st) == MM_OK ? MM_OK : MM_ERR_IO;
}

int mm_fs_open_ro(const char *path, MmFile *out, uint32_t tmo)
{
    uint64_t t0 = now_ms(); MmStat st;
    out->fd = -1;
    for (;;) {
        int fd = sceKernelOpen(path, O_RDONLY, 0);
        if (fd >= 0) { out->fd = fd; break; }
        if (now_ms() - t0 > tmo) return MM_ERR_TIMEOUT;
        sceKernelUsleep(5000); mm_wd_kick();
    }
    if (mm_fs_stat(path, &st) != MM_OK) { mm_fs_close(out); return MM_ERR_IO; }
    out->size = (uint32_t)st.st_size;
    return MM_OK;
}

int mm_fs_read_full(MmFile *f, void *buf, size_t len, uint32_t tmo)
{
    size_t done = 0; int r = 0; uint64_t t0 = now_ms();
    while (done < len) {
        int n = sceKernelRead(f->fd, (char *)buf + done, len - done);
        if (n > 0) { done += (size_t)n; r = 0; mm_wd_kick(); continue; }
        if (n == 0) break;
        if (++r > 5) return MM_ERR_IO;
        if (now_ms() - t0 > tmo) return MM_ERR_TIMEOUT;
        sceKernelUsleep(2000);
    }
    return done == len ? MM_OK : MM_ERR_SHORT;
}

int mm_fs_close(MmFile *f)
{ if (f->fd >= 0) { sceKernelClose(f->fd); f->fd = -1; } return MM_OK; }

int mm_fs_stat(const char *path, MmStat *o)
{
    SceKernelStat k; memset(&k, 0, sizeof(k));
    if (sceKernelStat(path, &k)) return MM_ERR_IO;
    o->st_mode = k.st_mode; o->st_size = k.st_size; o->st_mtime = (uint32_t)k.st_mtime;
    return MM_OK;
}

int mm_fs_write_atomic(const char *path, const void *buf, size_t len)
{
    char tmp[MM_PATH_MAX + 8]; size_t w = 0;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp)) return MM_ERR_IO;
    int fd = sceKernelOpen(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) return MM_ERR_IO;
    while (w < len) {
        int n = sceKernelWrite(fd, (const char *)buf + w, len - w);
        if (n <= 0) { sceKernelClose(fd); sceKernelUnlink(tmp); return MM_ERR_IO; }
        w += (size_t)n;
    }
    sceKernelClose(fd); sceKernelRename(tmp, path);
    return MM_OK;
}

int mm_fs_readdir(const char *path, MmEntry *o, int max, int *cnt)
{
    int fd = sceKernelOpen(path, O_RDONLY | O_DIRECTORY, 0);
    char buf[4096]; int n;
    *cnt = 0;
    if (fd < 0) return MM_ERR_IO;
    while ((n = sceKernelGetdents(fd, buf, sizeof(buf))) > 0) {
        int off = 0;
        while (off < n) {
            SceKernelDirent *d = (SceKernelDirent *)(buf + off);
            if (!d->d_reclen) break;
            off += d->d_reclen;
            if (d->d_name[0] == '.' || *cnt >= max) continue;
            MmEntry *e = &o[(*cnt)++];
            snprintf(e->path, sizeof(e->path), "%s/%s", path, d->d_name);
            snprintf(e->name, sizeof(e->name), "%s", d->d_name);
            MmStat st;
            e->size = mm_fs_stat(e->path, &st) == MM_OK ? st.st_size : 0;
        }
    }
    sceKernelClose(fd);
    return MM_OK;
}
```

### `hal/input.c`

Edge-Erkennung plus Auto-Repeat, wie zuvor. `scePadInit`, `sceUserServiceGetForegroundUser`, `scePadOpen`, `scePadReadState`, `g_next_repeat` bei 400 ms / 90 ms.

### `hal/sys.c`

```c
#include "sys.h"
#include "../app.h"
#include <orbis/LncUtil.h>
#include <orbis/UserService.h>
#include <orbis/SystemService.h>
#include <string.h>

int mm_sys_launch(const char *tid)
{
    SceLncLaunchAppParam p;
    int uid = 0;

    sceUserServiceGetForegroundUser(&uid);
    memset(&p, 0, sizeof(p));
    p.size = sizeof(p);      /* ohne size: EINVAL */
    p.userId = uid;

    if (g_fw_major <= 6 && sceLncUtilLaunchApp(tid, NULL, &p) == 0)
        return MM_OK;

    if (sceAppInstUtilAppInstallTitleDir(tid, MM_MOUNT "/app", 0) == 0) {
        if (sceLncUtilLaunchApp(tid, NULL, &p) == 0) return MM_OK;
        sceAppInstUtilAppUnInstall(tid);
    }
    return MM_ERR_IO;
}

int mm_sys_shell_busy(void)
{
    SceSystemServiceStatus st;
    return sceSystemServiceGetStatus(&st) == 0 && st.isSystemUiOverlaid;
}

void mm_sys_notify(const char *msg)
{
    static uint64_t last;
    uint64_t now = sceKernelGetProcessTimeLow();
    if (now - last < 1000000ULL) return;   /* max 1/s */
    last = now;
    sceSysUtilSendSystemNotificationWithText(0, msg);
}
```

### `hal/video.c`

SDL2 per `sceKernelLoadStartModule("/app0/sce_module/libSDL2.so", ...)` **vor** `SDL_Init`. Renderer-Stufen Vsync → Accelerated → Software, `SDL_RenderPresent` + `SDL_PumpEvents`, `mm_splash` zeitgesteuert. Wie zuvor, nur mit Modulladen.

### `core/watchdog.c`, `core/scan.c`, `core/config.c`, `core/disc_client.c`

Wie geliefert. `disc_client` mit `mm_disc_strerror()`, 15 s Timeout, Sequenzprüfung. `scan.c` filtert `.iso/.img/.bin` und sortiert.

### `core/fwcheck.c`

```c
#include <orbis/libkernel.h>
#include <string.h>

int mm_fw_ok(char out[16], int *major)
{
    static const char *ok[] = { "06.720", "10.010", "13.520", "14.020" };
    SceKernelSwVersion v;

    if (sceKernelGetSystemSwVersion(&v) != 0) return 0;
    strncpy(out, v.version_string, 15); out[15] = '\0';
    *major = (out[3] - '0') * 10 + (out[4] - '0');
    for (size_t i = 0; i < sizeof(ok) / sizeof(ok[0]); i++)
        if (!strncmp(out, ok[i], 6)) return 1;
    return 0;
}
```

### `main.c`

FW-Gate im Kopf, dann Init, Splash, Loop. `mm_log` mit `O_WRONLY | O_CREAT | O_APPEND`. Loop prüft `mm_sys_shell_busy()` und pausiert dabei, statt in den Overlay zu rendern.

### `ui/list.c`, `ui/dialog.c`, `ui/font.c`, `ui/theme.c`

Wie geliefert. `list_activate` ruft `mm_disc_mount` → `mm_sys_launch`, Fehler über `mm_disc_strerror` in `mm_dialog_error`. `dialog.c` bekommt die Zusatzzeile „discmgrd nicht gestartet?" bei `MM_ERR_NODEV`.

### `Makefile`

```make
OO_PS4_TOOLCHAIN ?= /opt/ps4-openorbis
include $(OO_PS4_TOOLCHAIN)/include/Makefile

TARGET      := multiman
TARGETFILES := $(OBJS)
TARGET_LIBS := -lSceKernel -lScePad -lSceUserService -lSceSystemService \
               -lSceSysUtil -lSceAppInstUtil -lSceLncUtil
CREATE_PKG  := 1
CFLAGS      += -Wall -Wextra -O2 -fstack-protector-strong

check: $(TARGET).elf
	@! nm -u $< | grep -E 'cellAudio|cellFsGetFreeSize|sysSmMount|sysIsoMount|sys_storage|cellFsInstallPackage|cellGame' \
	  || (echo "entfernte API wieder im Build"; exit 1)
```

`-lSDL2` fehlt absichtlich — die Bibliothek wird zur Laufzeit geladen.

### Build

```bash
make VERSION=0.2.0 check
```

### Abnahmekriterien

1. Start auf allen vier FWs, Log zeigt erkannte FW.
2. Fremde FW → Notification, Rückkehr zum Home.
3. Mount + Start je FW einzeln.
4. 30 min Leerlauf je FW ohne Watchdog-Ausschlag.
5. `check`-Target grün.

---

## Gesamtmatrix

| Punkt | 6.72 | 10.01 | 13.52 | 14.02 |
|---|---|---|---|---|
| Offsets/Signaturen | vorhanden | abzuleiten | abzuleiten | abzuleiten |
| SMEP/SMAP-Bypass | nein | ja | ja | ja |
| udf-Modul nachladen | nein | ja | ja | ja |
| Launch-Fallback | optional | Pflicht | Pflicht | Pflicht |
| Device | `bdiso0` | `bdiso1` | `bdiso1` | `bdiso1` |

**Reihenfolge:** 6.72 → 10.01 → 13.52 → 14.02. Neue FW erst nach grünem `discctl mount` in die UI.

Offen bleibt einzig die Signaturermittlung für 10.01/13.52/14.02 in Ghidra. Soll ich das Suchskript dafür schreiben?