#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/syscall.h>        /* For SYS_write etc */
#include <fcntl.h>

#include "faketime.h"

#define P(B64) (fprintf(stderr, "%s: %lld\n", #B64, B64))
#ifdef DEBUG
#define LOG(NAME, TIME) (fprintf(stderr, "UNIX Time returned by syscall (%s): %ld\n", NAME, TIME))
#else
#define LOG(NAME, TIME)
#endif

#ifndef __NR_time
#define __NR_time -1
#endif

static int exit_code = 0;

int get_syscall_number(pid_t pid)
{
#if defined(__x86_64__)
#if 1
	errno = 0;
	int offset = offsetof(struct user, regs.orig_rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	assert(errno == 0);
	return (int)val;
#else			/* another way */
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	return regs.orig_rax;
#endif
#elif defined(__i386__)
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	return regs.orig_eax;
#elif defined(__arm__)
	errno = 0;
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	return regs.ARM_r7;
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
  if (errno != 0) {
    fprintf(stderr, "errno=%d %s\n", errno, strerror(errno));
  }
	assert(errno == 0);
	switch (iov.iov_len) {
	case sizeof(struct user_pt_regs):
		return arm_regs_union.aarch64_r.regs[8];
	case sizeof(struct arm_pt_regs):
		return arm_regs_union.arm_r.ARM_r7;
	}
	return -1;
#endif
}

int get_retval(pid_t pid)
{
#if defined(__x86_64__)
#if 1
	errno = 0;
	int offset = offsetof(struct user, regs.rax);
	long val = ptrace(PTRACE_PEEKUSER, pid, offset);
	return (int)val;
#else			/* another way */
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.rax;
#endif
#elif defined(__i386__)
	errno = 0;
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.eax;
#elif defined(__arm__)
	errno = 0;
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	return regs.ARM_r0;
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	assert(errno == 0);
	switch (iov.iov_len) {
	case sizeof(struct user_pt_regs):
		return arm_regs_union.aarch64_r.regs[0];
	case sizeof(struct arm_pt_regs):
		return arm_regs_union.arm_r.ARM_r0;
	}
	return -1;
#endif
}

void set_retval(pid_t pid, long new_val)
{
#if defined(__x86_64__)
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	if ((long)regs.rax == new_val)
		return;
	regs.rax = new_val;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	assert(errno == 0);
#elif defined(__i386__)
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	if ((long)regs.eax == new_val)
		return;
	regs.eax = new_val;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	assert(errno == 0);
#elif defined(__arm__)
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	assert(errno == 0);
	if ((long)regs.ARM_r0 == new_val)
		return;
	regs.ARM_r0 = new_val;
	ptrace(PTRACE_SETREGS, pid, 0, &regs);
	assert(errno == 0);
#elif defined(__arm64__) || defined(__aarch64__)
	struct iovec iov = {
		.iov_base = &arm_regs_union,
		.iov_len = sizeof(struct user_pt_regs)
	};
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov);
	assert(errno == 0);
	switch (iov.iov_len) {
	case sizeof(struct user_pt_regs):
		arm_regs_union.aarch64_r.regs[0] = new_val;
	case sizeof(struct arm_pt_regs):
		arm_regs_union.arm_r.ARM_r0 = new_val;
	}
	ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov);
	assert(errno == 0);
#endif
}

long get_syscall_arg(pid_t pid, int order)
{
	long val;
#if defined(__x86_64__)
	int offset;

	switch (order) {
	case 0:
		offset = offsetof(struct user, regs.rdi);
		break;
	case 1:
		offset = offsetof(struct user, regs.rsi);
		break;
	case 2:
		offset = offsetof(struct user, regs.rdx);
		break;
	case 3:
		offset = offsetof(struct user, regs.r10);
		break;
	case 4:
		offset = offsetof(struct user, regs.r8);
		break;
	case 5:
		offset = offsetof(struct user, regs.r9);
		break;
	default:
		return -1;
	}
	errno = 0;
	val = ptrace(PTRACE_PEEKUSER, pid, offset);
	assert(errno == 0);
#elif defined(__i386__)
	struct user_regs_struct regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	switch (order) {
	case 0:
		val = regs.ebx;
		break;
	case 1:
		val = regs.ecx;
		break;
	case 2:
		val = regs.edx;
		break;
	case 3:
		val = regs.esi;
		break;
	case 4:
		val = regs.edi;
		break;
	case 5:
		val = regs.ebp;
		break;
	default:
		return -1;
	}
#elif defined(__arm__)
	struct pt_regs regs;
	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	switch (order) {
	case 0:
		val = regs.ARM_ORIG_r0;
		break;
	case 1:
		val = regs.ARM_r1;
		break;
	case 2:
		val = regs.ARM_r2;
		break;
	case 3:
		val = regs.ARM_r3;
		break;
	case 4:
		val = regs.ARM_r4;
		break;
	case 5:
		val = regs.ARM_r5;
		break;
	default:
		return -1;
	}
#elif defined(__arm64__) || defined(__aarch64__)
	switch (order) {
	case 0:
		val = arm_regs_union.aarch64_r.regs[0];
		break;
	case 1:
		val = arm_regs_union.aarch64_r.regs[1];
		break;
	case 2:
		val = arm_regs_union.aarch64_r.regs[2];
		break;
	case 3:
		val = arm_regs_union.aarch64_r.regs[3];
		break;
	case 4:
		val = arm_regs_union.aarch64_r.regs[4];
		break;
	case 5:
		val = arm_regs_union.aarch64_r.regs[5];
		break;
	default:
		return -1;
	}
#endif
	return val;
}

void getdata(pid_t child, long addr, char *dst, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;

	i = 0;
	j = len / sizeof(long);
	laddr = dst;
	while (i < j) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
		memcpy(laddr, data.chars, sizeof(long));
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
		memcpy(laddr, data.chars, j);
	}
}

void putdata(pid_t child, long addr, char *src, int len)
{
	char *laddr;
	int i, j;
	union u {
		long val;
		char chars[sizeof(long)];
	} data;

	i = 0;
	j = len / sizeof(long);
	laddr = src;
	while (i < j) {
		memcpy(data.chars, laddr, sizeof(long));
		ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
		++i;
		laddr += sizeof(long);
	}
	j = len % sizeof(long);
	if (j != 0) {
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, child, addr + i * 8, data.val);
	}
}

int main(int argc, char *argv[])
{
  pid_t child;
  int status;
  unsigned event;
  struct user_regs_struct regs;
  int sig;
  int counter = 0;
  int in_call1 = 0;
  int in_call2 = 0;
  int in_call3 = 0;

  unsigned long now = (unsigned long) time(NULL);

  if (argc < 3) {
    fprintf(stderr, "Usage:   %s unixtime command\n", basename(argv[0]));
    fprintf(stderr, "Example: %s 2147483647 date\n", basename(argv[0]));
    return -1;
  }

  unsigned long newtime = atoi(argv[1]);
  fprintf(stderr, "__NR_time=%d __NR_clock_gettime=%d __NR_gettimeofday=%d\n", __NR_time, __NR_clock_gettime, __NR_gettimeofday);

  child = fork();
  if (child < 0) {
    perror("fork");
    exit(errno);
  } else if (child == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    pid_t pid = getpid();
    /*
     * Induce a ptrace stop. Tracer (our parent)
     * will resume us with PTRACE_SYSCALL and display
     * the immediately following execve syscall.
     */
    kill(pid, SIGSTOP);
    execvp(argv[2], argv + 2);
  } else {
    fprintf(stderr, "Child started %d\n", child);
    wait(&status);
    if (ptrace(PTRACE_SETOPTIONS, child, 0,
        PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT) < 0) {
      perror("ptrace");
      exit(errno);
    }
    errno = 0;
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    struct timespec mono = {0};
    clock_gettime(CLOCK_MONOTONIC, &mono);
    while (1) {
      child = wait(&status);
      if (child < 0)
        return 0;
      event = ((unsigned)status >> 16);
      if (event != 0) {
        sig = 0;
        fprintf(stderr, "event != 0\n");
        goto end;
      }
      if (WIFSIGNALED(status) || WIFEXITED(status)
          || !WIFSTOPPED(status)) {
        exit_code = WEXITSTATUS(status);
        /* TODO free pinfp */
        fprintf(stderr, "exit_code = %d\n", exit_code);
        continue;
      }
      sig = WSTOPSIG(status);
      if (sig == SIGSTOP) {
        sig = 0;
        fprintf(stderr, "SIGSTOP\n");
        goto end;
      }
      if (sig != SIGTRAP) {
        siginfo_t si;
        int stopped =
            (ptrace(PTRACE_GETSIGINFO, child, 0, (long)&si) <
             0);
        if (!stopped) {
          /* It's signal-delivery-stop. Inject the signal */
          // fprintf(stderr, "!stopped, sig=%d\n", sig);
          // goto end;
        }
      }
      int csn = get_syscall_number(child);
      // fprintf(stderr, "csn=%d\n", csn);
      if (csn == __NR_time) {
        in_call1 ^= 1;
        if (1 || in_call1 == 0) {
          long arg1 = get_syscall_arg(child, 0);
          if (!arg1) {
            time_t rettime = get_retval(child);
            LOG("time", rettime);
            set_retval(child, time(NULL) - now + newtime);
          } else {
            time_t rettime = 0;
            getdata(child, arg1, (char *)&rettime, sizeof(rettime));
            LOG("time", rettime);
			rettime = time(NULL) - now + newtime;
            putdata(child, arg1, (char *)&rettime, sizeof(rettime));
          }
        }
      } else if (csn == __NR_clock_gettime) {
        in_call2 ^= 1;
        if (1 || in_call2 == 0) {
          long arg1 = get_syscall_arg(child, 0);
          if (arg1 == CLOCK_REALTIME) {
            long arg2 = get_syscall_arg(child, 1);
            struct timespec rettime = {0};
            struct timespec mono2 = {0};
            clock_gettime(CLOCK_MONOTONIC, &mono2);
            getdata(child, arg2, (char *)&rettime, sizeof(rettime));
            char sArg1[20];
            sprintf(sArg1, "clock_gettime %ld", arg1);
            LOG(sArg1, rettime.tv_sec);
            if (mono2.tv_nsec < mono.tv_nsec) {
              rettime.tv_sec = newtime + mono2.tv_sec - mono.tv_sec - 1;
              rettime.tv_nsec = 1000 * 1000000 + mono2.tv_nsec - mono.tv_nsec;
            } else {
              rettime.tv_sec = newtime + mono2.tv_sec - mono.tv_sec;
              rettime.tv_nsec = mono2.tv_nsec - mono.tv_nsec;
            }
            putdata(child, arg2, (char *)&rettime, sizeof(rettime));
          }
        }
      } else if (csn == __NR_gettimeofday) {
        in_call3 ^= 1;
        if (1 || in_call3 == 0) {
          long arg1 = get_syscall_arg(child, 0);
          struct timeval rettime = {0};
          getdata(child, arg1, (char *)&rettime, sizeof(rettime));
          LOG("gettimeofday", rettime.tv_sec);
          rettime.tv_sec = time(NULL) - now + newtime;
          rettime.tv_usec = 0;
          putdata(child, arg1, (char *)&rettime, sizeof(rettime));
        }
      }
      counter += in_call1 + in_call2 + in_call3;
      sig = 0;
end:
      errno = 0;
      if (ptrace(PTRACE_SYSCALL, child, 0, sig) < 0) {
        if (errno == ESRCH)
          continue;
        return -1;
      }
    }
  }
  return exit_code;
}
