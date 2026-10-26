/* AgenticVM guest service, protocol v1. Original implementation, no dependencies.
 * Build: cc -std=c11 -O2 -Wall -Wextra -Werror -static agent.c -o agenticvm-agent
 * Run as an unprivileged user: agenticvm-agent --workspace /workspace
 * The VM is the execution boundary. File RPCs are anchored to workspace; exec
 * intentionally runs ordinary Linux programs, not a filesystem sandbox.
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <grp.h>

#define LINE_MAX_BYTES (2u * 1024u * 1024u)
#define FILE_MAX_BYTES (1024u * 1024u)
#define OUTPUT_MAX_BYTES 65536u
#define TOKEN_MAX 1024
#define ARG_MAX_COUNT 64
#define JOB_MAX 8
#define RUNNING_MAX 2
#define DEFAULT_TIMEOUT_MS 30000u
#define MAX_TIMEOUT_MS 300000u

enum token_kind { J_STRING, J_NUMBER, J_OBJECT, J_ARRAY, J_BOOL, J_NULL };
struct token { enum token_kind kind; size_t start, end; int next, count; };
struct json { const char *s; size_t len, pos; struct token t[TOKEN_MAX]; int n; };
struct output { unsigned char bytes[OUTPUT_MAX_BYTES]; size_t len; int truncated, fd; };
struct job {
    int used, running, reaped, status, timed_out, cancelled;
    unsigned long number;
    pid_t pid;
    uint64_t deadline;
    struct output out, err;
};
static struct job jobs[JOB_MAX];
static unsigned long next_job = 1, next_file = 1;
static int workspace_fd = -1, stdio_mode = 0, signal_fd = -1;
static int input_disconnected;
static volatile sig_atomic_t quitting = 0;
static char *input_line;
static size_t input_used;
static int dropping_line;
static struct termios saved_tty;
static int restore_tty;
/* The init selects the profile; protocol requests cannot relax these limits.
 * Chromium reserves a large, sparse virtual address range for its sandbox and
 * JavaScript engine. Desktop physical memory is bounded by the VM, rather than
 * an address-space limit that would prevent an otherwise small browser boot.
 */
static int desktop_profile;
static int agent_profile;

static int child_environment(void) {
    if (clearenv() || setenv("PATH", "/bin:/usr/bin:/sbin:/usr/sbin", 1) ||
        setenv("HOME", "/workspace", 1) || setenv("LANG", "C.UTF-8", 1)) return -1;
    if (desktop_profile &&
        (setenv("DISPLAY", ":0", 1) || setenv("XAUTHORITY", "/workspace/.Xauthority", 1) ||
         setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1) ||
         setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus", 1))) return -1;
    return 0;
}

static int child_limits(void) {
    rlim_t descriptors = desktop_profile ? 1024u : 64u;
    rlim_t processes_count = desktop_profile ? 256u : 64u;
    rlim_t address_space = desktop_profile ? RLIM_INFINITY : 128u * 1024u * 1024u;
    rlim_t maximum_file = (desktop_profile ? 128u : 32u) * 1024u * 1024u;
    struct rlimit zero = {0, 0}, files = {descriptors, descriptors};
    struct rlimit processes = {processes_count, processes_count};
    struct rlimit memory = {address_space, address_space};
    struct rlimit file_size = {maximum_file, maximum_file};
    return setrlimit(RLIMIT_CORE, &zero) || setrlimit(RLIMIT_NOFILE, &files) ||
        setrlimit(RLIMIT_NPROC, &processes) || setrlimit(RLIMIT_AS, &memory) ||
        setrlimit(RLIMIT_FSIZE, &file_size);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void ws(struct json *j) {
    while (j->pos < j->len && (j->s[j->pos] == ' ' || j->s[j->pos] == '\t' || j->s[j->pos] == '\r' || j->s[j->pos] == '\n')) j->pos++;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_value(struct json *j, int depth) {
    if (depth > 16 || j->n == TOKEN_MAX) return -1;
    ws(j);
    if (j->pos == j->len) return -1;
    int idx = j->n++;
    struct token *t = &j->t[idx];
    t->start = j->pos;
    t->count = 0;
    char c = j->s[j->pos++];
    if (c == '"') {
        t->kind = J_STRING;
        t->start = j->pos;
        for (;;) {
            if (j->pos == j->len) return -1;
            unsigned char ch = (unsigned char)j->s[j->pos++];
            if (ch == '"') { t->end = j->pos - 1; break; }
            if (ch < 32) return -1;
            if (ch == '\\') {
                if (j->pos == j->len) return -1;
                ch = (unsigned char)j->s[j->pos++];
                if (ch == 'u') {
                    for (int k = 0; k < 4; k++) {
                        if (j->pos == j->len || hexval(j->s[j->pos++]) < 0) return -1;
                    }
                } else if (!ch || !strchr("\"\\/bfnrt", ch)) return -1;
            }
        }
    } else if (c == '{' || c == '[') {
        t->kind = c == '{' ? J_OBJECT : J_ARRAY;
        char close = c == '{' ? '}' : ']';
        ws(j);
        if (j->pos < j->len && j->s[j->pos] == close) j->pos++;
        else for (;;) {
            if (c == '{') {
                ws(j);
                if (j->pos == j->len || j->s[j->pos] != '"' || parse_value(j, depth + 1) < 0) return -1;
                ws(j);
                if (j->pos == j->len || j->s[j->pos++] != ':') return -1;
            }
            if (parse_value(j, depth + 1) < 0) return -1;
            t->count++;
            ws(j);
            if (j->pos == j->len) return -1;
            char sep = j->s[j->pos++];
            if (sep == close) break;
            if (sep != ',') return -1;
        }
        t->end = j->pos;
    } else if (c == 't' || c == 'f' || c == 'n') {
        const char *literal = c == 't' ? "true" : c == 'f' ? "false" : "null";
        size_t n = strlen(literal);
        if (t->start + n > j->len || memcmp(j->s + t->start, literal, n)) return -1;
        j->pos = t->start + n;
        t->kind = c == 'n' ? J_NULL : J_BOOL;
        t->end = j->pos;
    } else {
        t->kind = J_NUMBER;
        size_t p = t->start;
        if (j->s[p] == '-') p++;
        if (p == j->len) return -1;
        if (j->s[p] == '0') p++;
        else {
            if (j->s[p] < '1' || j->s[p] > '9') return -1;
            while (p < j->len && j->s[p] >= '0' && j->s[p] <= '9') p++;
        }
        if (p < j->len && j->s[p] == '.') {
            p++;
            size_t begin = p;
            while (p < j->len && j->s[p] >= '0' && j->s[p] <= '9') p++;
            if (p == begin) return -1;
        }
        if (p < j->len && (j->s[p] == 'e' || j->s[p] == 'E')) {
            p++;
            if (p < j->len && (j->s[p] == '+' || j->s[p] == '-')) p++;
            size_t begin = p;
            while (p < j->len && j->s[p] >= '0' && j->s[p] <= '9') p++;
            if (p == begin) return -1;
        }
        j->pos = p;
        t->end = p;
    }
    t->next = j->n;
    return idx;
}

static int string_is(struct json *j, int idx, const char *s) {
    if (idx < 0 || j->t[idx].kind != J_STRING) return 0;
    struct token *t = &j->t[idx];
    return t->end - t->start == strlen(s) && !memcmp(j->s + t->start, s, strlen(s));
}

/* Protocol keys are ASCII and may not use JSON escapes. Duplicate keys fail. */
static int property(struct json *j, int obj, const char *key) {
    if (obj < 0 || j->t[obj].kind != J_OBJECT) return -1;
    int found = -1;
    for (int i = obj + 1; i < j->t[obj].next;) {
        int value = i + 1;
        if (string_is(j, i, key)) {
            if (found >= 0) return -2;
            found = value;
        }
        i = j->t[value].next;
    }
    return found;
}

static int utf8(char *dst, size_t cap, size_t *n, unsigned cp) {
    unsigned char out[4];
    size_t k;
    if (cp == 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return -1;
    if (cp <= 0x7f) { out[0] = (unsigned char)cp; k = 1; }
    else if (cp <= 0x7ff) { out[0] = 0xc0 | (cp >> 6); out[1] = 0x80 | (cp & 63); k = 2; }
    else if (cp <= 0xffff) { out[0] = 0xe0 | (cp >> 12); out[1] = 0x80 | ((cp >> 6) & 63); out[2] = 0x80 | (cp & 63); k = 3; }
    else { out[0] = 0xf0 | (cp >> 18); out[1] = 0x80 | ((cp >> 12) & 63); out[2] = 0x80 | ((cp >> 6) & 63); out[3] = 0x80 | (cp & 63); k = 4; }
    if (*n + k >= cap) return -1;
    memcpy(dst + *n, out, k); *n += k;
    return 0;
}

static int json_string(struct json *j, int idx, char *dst, size_t cap) {
    if (idx < 0 || j->t[idx].kind != J_STRING || cap == 0) return -1;
    size_t n = 0;
    for (size_t p = j->t[idx].start; p < j->t[idx].end;) {
        unsigned char c = (unsigned char)j->s[p++];
        if (c == '\\') {
            c = (unsigned char)j->s[p++];
            if (c == 'u') {
                unsigned cp = 0;
                for (int k = 0; k < 4; k++) cp = (cp << 4) | (unsigned)hexval(j->s[p++]);
                if (cp >= 0xd800 && cp <= 0xdbff) {
                    if (p + 6 > j->t[idx].end || j->s[p] != '\\' || j->s[p + 1] != 'u') return -1;
                    p += 2;
                    unsigned low = 0;
                    for (int k = 0; k < 4; k++) low = (low << 4) | (unsigned)hexval(j->s[p++]);
                    if (low < 0xdc00 || low > 0xdfff) return -1;
                    cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                }
                if (utf8(dst, cap, &n, cp)) return -1;
                continue;
            }
            if (c == 'b') c = '\b'; else if (c == 'f') c = '\f';
            else if (c == 'n') c = '\n'; else if (c == 'r') c = '\r'; else if (c == 't') c = '\t';
        }
        if (!c || n + 1 >= cap) return -1;
        dst[n++] = (char)c;
    }
    dst[n] = 0;
    return 0;
}

static int uint_field(struct json *j, const char *key, unsigned def, unsigned min, unsigned max, unsigned *out) {
    int idx = property(j, 0, key);
    if (idx == -1) { *out = def; return 0; }
    if (idx < 0 || j->t[idx].kind != J_NUMBER) return -1;
    unsigned long val = 0;
    for (size_t p = j->t[idx].start; p < j->t[idx].end; p++) {
        if (j->s[p] < '0' || j->s[p] > '9') return -1;
        val = val * 10 + (unsigned)(j->s[p] - '0');
        if (val > max) return -1;
    }
    if (val < min) return -1;
    *out = (unsigned)val;
    return 0;
}

static void quote(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 32) printf("\\u%04x", (unsigned)*p);
        else putchar(*p);
    }
    putchar('"');
}

static void begin_reply(const char *id) {
    fputs("{\"v\":1,\"id\":", stdout); quote(id); fputs(",\"ok\":true,\"result\":", stdout);
}
static void end_reply(void) { fputs("}\n", stdout); fflush(stdout); }
static void error_reply(const char *id, const char *code, const char *message) {
    fputs("{\"v\":1,\"id\":", stdout); quote(id);
    fputs(",\"ok\":false,\"error\":{\"code\":", stdout); quote(code);
    fputs(",\"message\":", stdout); quote(message); fputs("}}\n", stdout); fflush(stdout);
}

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_print(const unsigned char *data, size_t n) {
    putchar('"');
    for (size_t i = 0; i < n; i += 3) {
        unsigned a = data[i], b = i + 1 < n ? data[i + 1] : 0, c = i + 2 < n ? data[i + 2] : 0;
        putchar(base64_chars[a >> 2]); putchar(base64_chars[((a & 3) << 4) | (b >> 4)]);
        putchar(i + 1 < n ? base64_chars[((b & 15) << 2) | (c >> 6)] : '=');
        putchar(i + 2 < n ? base64_chars[c & 63] : '=');
    }
    putchar('"');
}
static int base64_value(unsigned char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    return c == '+' ? 62 : c == '/' ? 63 : -1;
}
static int base64_decode(const char *s, unsigned char *data, size_t *size) {
    size_t n = strlen(s), used = 0;
    if (n % 4 || n > ((FILE_MAX_BYTES + 2u) / 3u) * 4u) return -1;
    for (size_t i = 0; i < n; i += 4) {
        int a = base64_value((unsigned char)s[i]), b = base64_value((unsigned char)s[i + 1]);
        int c = s[i + 2] == '=' ? 0 : base64_value((unsigned char)s[i + 2]);
        int d = s[i + 3] == '=' ? 0 : base64_value((unsigned char)s[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        int pad = s[i + 2] == '=' ? 2 : s[i + 3] == '=' ? 1 : 0;
        if ((pad && i + 4 != n) || (pad == 2 && s[i + 3] != '=') ||
            (pad == 2 && (b & 15)) || (pad == 1 && (c & 3))) return -1;
        if (used + (size_t)(3 - pad) > FILE_MAX_BYTES) return -1;
        data[used++] = (unsigned char)((a << 2) | (b >> 4));
        if (pad < 2) data[used++] = (unsigned char)((b << 4) | (c >> 2));
        if (pad == 0) data[used++] = (unsigned char)((c << 6) | d);
    }
    *size = used;
    return 0;
}

/* Convert the public namespace into a relative path, rejecting traversal.
 * Every subsequent directory walk uses openat + O_NOFOLLOW, including cwd.
 */
static int normalize_path(const char *path, char *out, size_t cap) {
    if (path[0] == '/') {
        if (strncmp(path, "/workspace", 10) || (path[10] && path[10] != '/')) return -1;
        path += 10;
    }
    size_t n = 0;
    while (*path) {
        while (*path == '/') path++;
        if (!*path) break;
        const char *end = strchr(path, '/');
        size_t k = end ? (size_t)(end - path) : strlen(path);
        if (k == 2 && path[0] == '.' && path[1] == '.') return -1;
        if (!(k == 1 && path[0] == '.')) {
            if (k > NAME_MAX || n + k + 1 >= cap) return -1;
            if (n) out[n++] = '/';
            memcpy(out + n, path, k); n += k;
        }
        path += k;
    }
    out[n] = 0;
    return 0;
}
static int parent_fd(const char *relative, char *leaf) {
    char buf[PATH_MAX];
    if (!*relative || strlen(relative) >= sizeof(buf)) { errno = EINVAL; return -1; }
    strcpy(buf, relative);
    int fd = dup(workspace_fd);
    if (fd < 0) return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    char *part = buf;
    for (;;) {
        char *slash = strchr(part, '/');
        if (!slash) { strcpy(leaf, part); return fd; }
        *slash = 0;
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(fd);
        if (next < 0) return -1;
        fd = next; part = slash + 1;
    }
}
static int open_directory(const char *relative) {
    if (!*relative) return fcntl(workspace_fd, F_DUPFD_CLOEXEC, 3);
    char leaf[NAME_MAX + 1];
    int parent = parent_fd(relative, leaf);
    if (parent < 0) return -1;
    int fd = openat(parent, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(parent); return fd;
}
static int request_path(struct json *j, const char *key, const char *def, char *relative) {
    char path[PATH_MAX];
    int idx = property(j, 0, key);
    if (idx == -1 && def) strcpy(path, def);
    else if (json_string(j, idx, path, sizeof(path))) return -1;
    return normalize_path(path, relative, PATH_MAX);
}

static void drain_output(struct output *out, size_t limit) {
    if (out->fd < 0) return;
    unsigned char buf[4096];
    /* Bound work per tick even if a child continuously floods the pipe. */
    for (int count = 0; count < 16; count++) {
        ssize_t n = read(out->fd, buf, sizeof(buf));
        if (n == 0) { close(out->fd); out->fd = -1; return; }
        if (n < 0) {
            if (errno != EAGAIN && errno != EINTR) { close(out->fd); out->fd = -1; }
            return;
        }
        size_t keep = (size_t)n;
        if (keep > limit - out->len) { keep = limit - out->len; out->truncated = 1; }
        if (keep) { memcpy(out->bytes + out->len, buf, keep); out->len += keep; }
    }
}
/* Per-job output cap stored separately so the capture arrays stay fixed size. */
static size_t job_limits[JOB_MAX];
static void service_jobs(void) {
    uint64_t now = now_ms();
    for (int i = 0; i < JOB_MAX; i++) {
        struct job *job = &jobs[i];
        if (!job->used || !job->running) continue;
        drain_output(&job->out, job_limits[i]); drain_output(&job->err, job_limits[i]);
        if (!job->reaped) {
            pid_t result = waitpid(job->pid, &job->status, WNOHANG);
            if (result == job->pid) {
                job->reaped = 1;
                /* Descendants must not outlive a completed execution job. */
                kill(-job->pid, SIGKILL);
            }
        }
        if (!job->reaped && job->deadline && now >= job->deadline) {
            job->timed_out = 1; kill(-job->pid, SIGKILL);
        }
        if (job->reaped && job->out.fd < 0 && job->err.fd < 0) job->running = 0;
    }
    /* Reap adopted grandchildren (Linux subreaper), never claim them as jobs. */
    for (;;) {
        int status;
        pid_t p = waitpid(-1, &status, WNOHANG);
        if (p <= 0) break;
        for (int i = 0; i < JOB_MAX; i++) if (jobs[i].used && jobs[i].pid == p && !jobs[i].reaped) {
            jobs[i].status = status; jobs[i].reaped = 1; kill(-p, SIGKILL);
        }
    }
}

static void consume_signals(void) {
    struct signalfd_siginfo signals[8];
    for (int batch = 0; batch < 16; batch++) {
        ssize_t count = read(signal_fd, signals, sizeof(signals));
        if (count <= 0) break;
        size_t n = (size_t)count / sizeof(signals[0]);
        for (size_t i = 0; i < n; i++) if (signals[i].ssi_signo == SIGIO) input_disconnected = 0;
    }
}

/* No timer is armed for an idle guest. A job's wall deadline, output pipe,
 * SIGCHLD, or input/connection notification supplies the next real event.
 */
static int deadline_timeout(int maximum) {
    uint64_t now = now_ms();
    int timeout = maximum;
    for (int i = 0; i < JOB_MAX; i++) {
        struct job *job = &jobs[i];
        if (!job->used || !job->running || job->reaped || !job->deadline || job->timed_out || job->cancelled) continue;
        uint64_t left = job->deadline > now ? job->deadline - now : 0;
        int wait = left > INT_MAX ? INT_MAX : (int)left;
        if (timeout < 0 || wait < timeout) timeout = wait;
    }
    return timeout;
}

static void wait_job_events(int maximum) {
    struct pollfd fds[1 + JOB_MAX * 2];
    int count = 1;
    fds[0] = (struct pollfd){signal_fd, POLLIN, 0};
    for (int i = 0; i < JOB_MAX; i++) if (jobs[i].used && jobs[i].running) {
        if (jobs[i].out.fd >= 0) fds[count++] = (struct pollfd){jobs[i].out.fd, POLLIN, 0};
        if (jobs[i].err.fd >= 0) fds[count++] = (struct pollfd){jobs[i].err.fd, POLLIN, 0};
    }
    poll(fds, (nfds_t)count, deadline_timeout(maximum));
    if (fds[0].revents & POLLIN) consume_signals();
    service_jobs();
}
static struct job *get_job(struct json *j) {
    char id[32];
    if (json_string(j, property(j, 0, "job_id"), id, sizeof(id))) return NULL;
    for (int i = 0; i < JOB_MAX; i++) {
        char expected[32]; snprintf(expected, sizeof(expected), "%lu", jobs[i].number);
        if (jobs[i].used && !strcmp(id, expected)) return &jobs[i];
    }
    return NULL;
}
static void job_snapshot(const char *id, struct job *job) {
    begin_reply(id);
    printf("{\"job_id\":\"%lu\",\"state\":\"%s\",\"stdout_b64\":", job->number, job->running ? "running" : "exited");
    base64_print(job->out.bytes, job->out.len); fputs(",\"stderr_b64\":", stdout); base64_print(job->err.bytes, job->err.len);
    printf(",\"stdout_truncated\":%s,\"stderr_truncated\":%s,\"timed_out\":%s,\"cancelled\":%s",
        job->out.truncated ? "true" : "false", job->err.truncated ? "true" : "false",
        job->timed_out ? "true" : "false", job->cancelled ? "true" : "false");
    if (!job->running) {
        if (WIFEXITED(job->status)) printf(",\"exit_code\":%d,\"signal\":0", WEXITSTATUS(job->status));
        else printf(",\"exit_code\":%d,\"signal\":%d", 128 + WTERMSIG(job->status), WTERMSIG(job->status));
    }
    putchar('}'); end_reply();
}

static void execute_request(struct json *j, const char *id) {
    unsigned timeout, limit;
    if (uint_field(j, "timeout_ms", DEFAULT_TIMEOUT_MS, (desktop_profile || agent_profile) ? 0 : 1, MAX_TIMEOUT_MS, &timeout) ||
        uint_field(j, "output_limit", OUTPUT_MAX_BYTES, 0, OUTPUT_MAX_BYTES, &limit)) {
        error_reply(id, "invalid_argument", "Invalid timeout_ms or output_limit"); return;
    }
    int array = property(j, 0, "argv");
    if (array < 0 || j->t[array].kind != J_ARRAY || j->t[array].count < 1 || j->t[array].count > ARG_MAX_COUNT) {
        error_reply(id, "invalid_argument", "argv must contain 1 to 64 strings"); return;
    }
    char *argv[ARG_MAX_COUNT + 1] = {0};
    size_t total = 0;
    int argc = 0, valid = 1;
    for (int i = array + 1; i < j->t[array].next; i = j->t[i].next) {
        size_t size = j->t[i].end - j->t[i].start + 1;
        if (size > 16385 || total + size > 65536 || j->t[i].kind != J_STRING) { valid = 0; break; }
        argv[argc] = malloc(size);
        if (!argv[argc] || json_string(j, i, argv[argc], size)) { valid = 0; break; }
        total += size; argc++;
    }
    if (!valid || argc != j->t[array].count || !argv[0] || !argv[0][0]) {
        for (int k = 0; k <= argc; k++) free(argv[k]);
        error_reply(id, "invalid_argument", "Invalid argv or argument size limit exceeded"); return;
    }
    char relative[PATH_MAX];
    int cwd = request_path(j, "cwd", "/workspace", relative) ? -1 : open_directory(relative);
    if (cwd < 0) {
        for (int k = 0; k < argc; k++) free(argv[k]);
        error_reply(id, "invalid_path", "cwd must be a real directory inside /workspace"); return;
    }
    int running = 0, slot = -1;
    for (int i = 0; i < JOB_MAX; i++) { if (jobs[i].running) running++; if (!jobs[i].used && slot < 0) slot = i; }
    if (running >= RUNNING_MAX || slot < 0) {
        close(cwd); for (int k = 0; k < argc; k++) free(argv[k]);
        error_reply(id, "busy", running >= RUNNING_MAX ? "Two jobs already running" : "Retained job limit reached; forget completed jobs"); return;
    }
    int out[2] = {-1, -1}, err[2] = {-1, -1};
    if (pipe2(out, O_CLOEXEC) || pipe2(err, O_CLOEXEC)) {
        if (out[0] >= 0) { close(out[0]); close(out[1]); }
        close(cwd); for (int k = 0; k < argc; k++) free(argv[k]);
        error_reply(id, "system_error", "Cannot create output pipes"); return;
    }
    pid_t child = fork();
    if (child == 0) {
        setpgid(0, 0);
        sigset_t unblocked;
        sigemptyset(&unblocked); sigprocmask(SIG_SETMASK, &unblocked, NULL);
        signal(SIGPIPE, SIG_DFL); signal(SIGTERM, SIG_DFL); signal(SIGINT, SIG_DFL);
        int nullfd = open("/dev/null", O_RDONLY);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0 || dup2(out[1], STDOUT_FILENO) < 0 || dup2(err[1], STDERR_FILENO) < 0 || fchdir(cwd)) _exit(126);
        close(nullfd); close(cwd); close(out[0]); close(out[1]); close(err[0]); close(err[1]);
        close(workspace_fd); close(signal_fd);
        if (child_limits()) {
            dprintf(STDERR_FILENO, "Cannot apply command resource limits: %s\n", strerror(errno)); _exit(126);
        }
        if (child_environment()) {
            dprintf(STDERR_FILENO, "Cannot apply command environment: %s\n", strerror(errno)); _exit(126);
        }
        execvp(argv[0], argv);
        int exec_error = errno;
        dprintf(STDERR_FILENO, "exec: %s: %s\n", argv[0], strerror(exec_error));
        _exit(exec_error == ENOENT ? 127 : 126);
    }
    close(cwd); close(out[1]); close(err[1]);
    for (int k = 0; k < argc; k++) free(argv[k]);
    if (child < 0) {
        close(out[0]); close(err[0]); error_reply(id, "system_error", "Cannot fork execution job"); return;
    }
    setpgid(child, child);
    fcntl(out[0], F_SETFL, O_NONBLOCK); fcntl(err[0], F_SETFL, O_NONBLOCK);
    struct job *job = &jobs[slot]; memset(job, 0, sizeof(*job));
    job->used = job->running = 1; job->pid = child; job->number = next_job++;
    job->deadline = timeout ? now_ms() + timeout : 0; job->out.fd = out[0]; job->err.fd = err[0]; job_limits[slot] = limit;
    begin_reply(id); printf("{\"job_id\":\"%lu\"}", job->number); end_reply();
}

static void file_request(struct json *j, const char *id, const char *op) {
    char relative[PATH_MAX], leaf[NAME_MAX + 1];
    if (request_path(j, "path", NULL, relative)) { error_reply(id, "invalid_path", "Path must be inside /workspace without parent traversal"); return; }
    if (!*relative && !strcmp(op, "stat")) {
        struct stat st;
        if (fstat(workspace_fd, &st)) error_reply(id, "io_error", "Cannot stat workspace");
        else { begin_reply(id); printf("{\"type\":\"directory\",\"size\":%llu}", (unsigned long long)st.st_size); end_reply(); }
        return;
    }
    int parent = parent_fd(relative, leaf);
    if (parent < 0) { error_reply(id, "invalid_path", "Parent directory is missing or contains a symlink"); return; }
    if (!strcmp(op, "stat")) {
        struct stat st;
        if (fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW)) error_reply(id, "io_error", "Cannot stat path");
        else if (S_ISLNK(st.st_mode)) error_reply(id, "invalid_path", "Symlinks are not accepted");
        else { begin_reply(id); printf("{\"type\":\"%s\",\"size\":%llu}", S_ISREG(st.st_mode) ? "file" : S_ISDIR(st.st_mode) ? "directory" : "other", (unsigned long long)st.st_size); end_reply(); }
    } else if (!strcmp(op, "read_file")) {
        int fd = openat(parent, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode)) error_reply(id, "invalid_path", "Path must name a regular file without symlinks");
        else if (st.st_size < 0 || st.st_size > FILE_MAX_BYTES) error_reply(id, "size_limit", "File exceeds 1 MiB");
        else {
            unsigned char *buf = malloc(FILE_MAX_BYTES + 1u);
            size_t used = 0;
            int failed = !buf;
            while (!failed && used <= FILE_MAX_BYTES) {
                ssize_t n = read(fd, buf + used, FILE_MAX_BYTES + 1u - used);
                if (n == 0) break;
                if (n < 0) { if (errno == EINTR) continue; failed = 1; break; }
                used += (size_t)n;
            }
            if (failed) error_reply(id, "io_error", "Cannot read file");
            else if (used > FILE_MAX_BYTES) error_reply(id, "size_limit", "File grew beyond 1 MiB");
            else { begin_reply(id); printf("{\"size\":%zu,\"data_b64\":", used); base64_print(buf, used); putchar('}'); end_reply(); }
            free(buf);
        }
        if (fd >= 0) close(fd);
    } else {
        int tok = property(j, 0, "data_b64");
        size_t encoded_cap = ((FILE_MAX_BYTES + 2u) / 3u) * 4u + 1u;
        char *encoded = malloc(encoded_cap);
        unsigned char *data = malloc(FILE_MAX_BYTES);
        size_t size = 0;
        if (!encoded || !data) error_reply(id, "system_error", "Out of memory");
        else if (json_string(j, tok, encoded, encoded_cap) || base64_decode(encoded, data, &size)) error_reply(id, "invalid_argument", "Invalid base64 or decoded file exceeds 1 MiB");
        else {
            struct stat st;
            int exists = fstatat(parent, leaf, &st, AT_SYMLINK_NOFOLLOW) == 0;
            if ((exists && !S_ISREG(st.st_mode)) || (!exists && errno != ENOENT)) error_reply(id, "invalid_path", "Destination must be a regular file without symlinks");
            else {
                char temporary[80]; snprintf(temporary, sizeof(temporary), ".agenticvm-%ld-%lu.tmp", (long)getpid(), next_file++);
                int fd = openat(parent, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
                int failed = fd < 0;
                size_t written = 0;
                while (!failed && written < size) {
                    ssize_t n = write(fd, data + written, size - written);
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) failed = 1; else written += (size_t)n;
                }
                if (fd >= 0 && close(fd)) failed = 1;
                if (!failed && renameat(parent, temporary, parent, leaf)) failed = 1;
                if (failed) { unlinkat(parent, temporary, 0); error_reply(id, "io_error", "Cannot atomically write file"); }
                else { begin_reply(id); printf("{\"size\":%zu}", size); end_reply(); }
            }
        }
        free(encoded); free(data);
    }
    close(parent);
}

static void handle_line(const char *line, size_t len) {
    struct json j = {.s = line, .len = len};
    int parsed = parse_value(&j, 0);
    ws(&j);
    if (parsed != 0 || j.pos != j.len || j.t[0].kind != J_OBJECT) { error_reply("", "invalid_json", "Expected a JSON object"); return; }
    char id[129], op[32];
    if (json_string(&j, property(&j, 0, "id"), id, sizeof(id))) { error_reply("", "invalid_argument", "id must be a string of at most 128 bytes"); return; }
    unsigned version;
    int v = property(&j, 0, "v");
    if (v < 0 || uint_field(&j, "v", 0, 1, 1, &version)) { error_reply(id, "unsupported_version", "Protocol v must equal 1"); return; }
    if (json_string(&j, property(&j, 0, "op"), op, sizeof(op))) { error_reply(id, "invalid_argument", "op must be a string"); return; }
    service_jobs();
    if (!strcmp(op, "ping")) {
        begin_reply(id);
        printf("{\"protocol\":1,\"uid\":%lu,\"gid\":%lu,\"pid\":%ld,\"profile\":\"%s\",\"workspace\":\"/workspace\",\"max_running_jobs\":2,\"max_retained_jobs\":8,\"max_file_bytes\":%u,\"max_output_bytes\":%u,\"display\":%s,\"limits\":{\"address_space_bytes\":%s,\"max_file_bytes\":%u,\"max_descriptors\":%u,\"max_uid_processes\":%u,\"persistent_jobs\":%s}}", (unsigned long)getuid(), (unsigned long)getgid(), (long)getpid(), desktop_profile ? "desktop" : agent_profile ? "agent" : "command", FILE_MAX_BYTES, OUTPUT_MAX_BYTES, desktop_profile ? "\":0\"" : "null", desktop_profile ? "null" : "134217728", (desktop_profile ? 128u : 32u) * 1024u * 1024u, desktop_profile ? 1024u : 64u, desktop_profile ? 256u : 64u, (desktop_profile || agent_profile) ? "true" : "false");
        end_reply();
    } else if (!strcmp(op, "exec")) execute_request(&j, id);
    else if (!strcmp(op, "poll") || !strcmp(op, "cancel") || !strcmp(op, "forget")) {
        struct job *job = get_job(&j);
        if (!job) { error_reply(id, "unknown_job", "No such retained job"); return; }
        if (!strcmp(op, "cancel")) {
            if (job->running) { job->cancelled = 1; kill(-job->pid, SIGKILL); }
            begin_reply(id); printf("{\"job_id\":\"%lu\",\"cancelled\":%s}", job->number, job->cancelled ? "true" : "false"); end_reply();
        } else if (!strcmp(op, "forget")) {
            if (job->running) error_reply(id, "busy", "Cannot forget a running job");
            else { memset(job, 0, sizeof(*job)); begin_reply(id); fputs("{\"forgotten\":true}", stdout); end_reply(); }
        } else {
            unsigned wait_ms;
            if (uint_field(&j, "wait_ms", 0, 0, 1000, &wait_ms)) { error_reply(id, "invalid_argument", "wait_ms must be from 0 to 1000"); return; }
            uint64_t end = now_ms() + wait_ms;
            while (job->running && now_ms() < end) {
                uint64_t now = now_ms();
                uint64_t left = end > now ? end - now : 0;
                wait_job_events(left > INT_MAX ? INT_MAX : (int)left);
            }
            job_snapshot(id, job);
        }
    } else if (!strcmp(op, "stat") || !strcmp(op, "read_file") || !strcmp(op, "write_file")) file_request(&j, id, op);
    else if (!strcmp(op, "shutdown")) { begin_reply(id); fputs("{\"shutting_down\":true}", stdout); end_reply(); quitting = 1; }
    else error_reply(id, "unknown_operation", "Unknown operation");
}

static void stop_handler(int sig) { (void)sig; quitting = 1; }
static void restore_terminal(void) { if (restore_tty) tcsetattr(STDIN_FILENO, TCSANOW, &saved_tty); }
int main(int argc, char **argv) {
    const char *workspace = "/workspace";
    int drop_uid = 0, drop_gid = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--stdio")) stdio_mode = 1;
        else if (!strcmp(argv[i], "--workspace") && i + 1 < argc) workspace = argv[++i];
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc &&
                 (!strcmp(argv[i + 1], "command") || !strcmp(argv[i + 1], "desktop") || !strcmp(argv[i + 1], "agent"))) {
            desktop_profile = !strcmp(argv[++i], "desktop");
            agent_profile = !strcmp(argv[i], "agent");
        }
        else if (!strcmp(argv[i], "--uid") && i + 1 < argc && !strcmp(argv[i + 1], "1000")) { drop_uid = 1; i++; }
        else if (!strcmp(argv[i], "--gid") && i + 1 < argc && !strcmp(argv[i + 1], "1000")) { drop_gid = 1; i++; }
        else { fprintf(stderr, "Usage: %s [--stdio] [--workspace PATH] [--profile command|desktop|agent] [--uid 1000 --gid 1000]\n", argv[0]); return 2; }
    }
    if (getuid() != geteuid() || getgid() != getegid()) { fputs("agenticvm-agent refuses set-ID execution\n", stderr); return 2; }
    if (getuid() == 0) {
        if (!drop_uid || !drop_gid || setgroups(0, NULL) || setgid(1000) || setuid(1000)) {
            fputs("Root launch requires a successful --uid 1000 --gid 1000 privilege drop\n", stderr); return 2;
        }
    } else if ((drop_uid && getuid() != 1000) || (drop_gid && getgid() != 1000)) {
        fputs("Requested UID/GID 1000 does not match the current user\n", stderr); return 2;
    }
    if (getuid() == 0 || geteuid() == 0) { fputs("agenticvm-agent refuses UID 0\n", stderr); return 2; }
    umask(0077);
    workspace_fd = open(workspace, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (workspace_fd < 0) { perror("workspace"); return 2; }
    input_line = malloc(LINE_MAX_BYTES + 1u);
    if (!input_line) { fputs("Out of memory\n", stderr); return 2; }
    struct stat input_stat;
    int reconnectable_device = fstat(STDIN_FILENO, &input_stat) == 0 && S_ISCHR(input_stat.st_mode);
    if (isatty(STDIN_FILENO)) {
        struct termios raw;
        if (tcgetattr(STDIN_FILENO, &saved_tty)) { perror("tcgetattr"); return 2; }
        raw = saved_tty; cfmakeraw(&raw); raw.c_cflag |= CLOCAL | CREAD; raw.c_cflag &= ~HUPCL;
        cfsetispeed(&raw, B115200); cfsetospeed(&raw, B115200);
        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw)) { perror("tcsetattr"); return 2; }
        restore_tty = 1; atexit(restore_terminal);
    }
    /* A virtio port must be opened once for both directions. stdin/stdout then
     * share one open-file description, including O_NONBLOCK. Output must stay
     * blocking to preserve complete JSON frames under transport backpressure.
     * Input temporarily toggles nonblocking around read, restoring it before
     * processing requests, to avoid stale poll-HUP races across reconnects.
     */
    int output_flags = fcntl(STDOUT_FILENO, F_GETFL);
    if (output_flags < 0 || fcntl(STDOUT_FILENO, F_SETFL, output_flags & ~O_NONBLOCK)) {
        perror("stdout flags"); close(workspace_fd); free(input_line); return 2;
    }
    if (!reconnectable_device) {
        int input_flags = fcntl(STDIN_FILENO, F_GETFL);
        if (input_flags < 0 || fcntl(STDIN_FILENO, F_SETFL, input_flags | O_NONBLOCK)) {
            perror("stdin flags"); close(workspace_fd); free(input_line); return 2;
        }
    }
    signal(SIGPIPE, SIG_IGN); signal(SIGTERM, stop_handler); signal(SIGINT, stop_handler);
    sigset_t watched_signals;
    sigemptyset(&watched_signals); sigaddset(&watched_signals, SIGCHLD);
    if (reconnectable_device && !stdio_mode) sigaddset(&watched_signals, SIGIO);
    if (sigprocmask(SIG_BLOCK, &watched_signals, NULL) ||
        (signal_fd = signalfd(-1, &watched_signals, SFD_NONBLOCK | SFD_CLOEXEC)) < 0) {
        perror("signalfd"); close(workspace_fd); free(input_line); return 2;
    }
    if (reconnectable_device && !stdio_mode) {
        int input_flags = fcntl(STDIN_FILENO, F_GETFL);
        if (input_flags < 0 || fcntl(STDIN_FILENO, F_SETOWN, getpid()) ||
            fcntl(STDIN_FILENO, F_SETFL, input_flags | O_ASYNC)) {
            perror("input async notifications"); close(signal_fd); close(workspace_fd); free(input_line); return 2;
        }
    }
    int input_blocking_flags = fcntl(STDIN_FILENO, F_GETFL);
    if (input_blocking_flags < 0) {
        perror("stdin flags"); close(signal_fd); close(workspace_fd); free(input_line); return 2;
    }
    input_blocking_flags &= ~O_NONBLOCK;
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl"); close(workspace_fd); free(input_line); return 2;
    }
    while (!quitting) {
        service_jobs();
        struct pollfd fds[2 + JOB_MAX * 2];
        int count = 2;
        fds[0] = (struct pollfd){input_disconnected ? -1 : STDIN_FILENO, POLLIN, 0};
        fds[1] = (struct pollfd){signal_fd, POLLIN, 0};
        for (int i = 0; i < JOB_MAX; i++) if (jobs[i].used && jobs[i].running) {
            if (jobs[i].out.fd >= 0) fds[count++] = (struct pollfd){jobs[i].out.fd, POLLIN, 0};
            if (jobs[i].err.fd >= 0) fds[count++] = (struct pollfd){jobs[i].err.fd, POLLIN, 0};
        }
        int result = poll(fds, (nfds_t)count, deadline_timeout(-1));
        if (result < 0 && errno != EINTR) break;
        if (fds[1].revents & POLLIN) consume_signals();
        if (fds[0].revents & (POLLIN | POLLHUP)) {
            char buf[8192];
            if (reconnectable_device && fcntl(STDIN_FILENO, F_SETFL, input_blocking_flags | O_NONBLOCK)) break;
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            int read_error = errno;
            if (reconnectable_device && fcntl(STDIN_FILENO, F_SETFL, input_blocking_flags)) break;
            errno = read_error;
            if (n == 0) {
                if (stdio_mode || !reconnectable_device) quitting = 1;
                else input_disconnected = 1;
            } else if (n < 0 && errno != EAGAIN && errno != EINTR) {
                perror("control channel"); quitting = 1;
            } else if (n > 0) for (ssize_t i = 0; i < n && !quitting; i++) {
                if (buf[i] == '\n') {
                    if (dropping_line) error_reply("", "line_too_large", "Request exceeds 2 MiB");
                    else if (input_used) { input_line[input_used] = 0; handle_line(input_line, input_used); }
                    input_used = 0; dropping_line = 0;
                } else if (!dropping_line) {
                    if (input_used == LINE_MAX_BYTES) { dropping_line = 1; input_used = 0; }
                    else input_line[input_used++] = buf[i];
                }
            }
        }
    }
    for (int i = 0; i < JOB_MAX; i++) if (jobs[i].used && jobs[i].running) kill(-jobs[i].pid, SIGKILL);
    uint64_t deadline = now_ms() + 1000;
    while (now_ms() < deadline) {
        service_jobs();
        int active = 0;
        for (int i = 0; i < JOB_MAX; i++) active += jobs[i].running;
        if (!active) break;
        uint64_t now = now_ms();
        uint64_t left = deadline > now ? deadline - now : 0;
        wait_job_events(left > INT_MAX ? INT_MAX : (int)left);
    }
    close(signal_fd); close(workspace_fd); free(input_line); return 0;
}
