#define _GNU_SOURCE

#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include<fcntl.h>
#include <stdio.h>

#define SYSROOT_DIR "./sysroot-debian-bullseye"
#define STACK_SIZE (16*1024*1024)
#define STR_BUF_SIZE 1024

//chrootしてディレクトリ変更
int chroot_dir(const char* const path){
    if(chroot(path) != 0) return -1;
    if(chdir("/") != 0) return -1;
    return 0;
}


//
typedef struct {
    int fd[2];          //親プロセスが準備している間待つようにする
} isolated_child_args_t;


#define SHELL_PATH "/bin/bash"

//コマンドを実行する関数cloneで使用
int exec_command_child(void *arg) {
    char *const argv[] = {SHELL_PATH, "-c", arg, NULL}, *const envp[] = {NULL};
    execve(SHELL_PATH, argv, envp);
    return -1;
}

//コマンドを実行する関数
int exec_command(void *cmd) {
    char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) return -1;
    pid_t child = clone((int (*)(void *)) exec_command_child, stack + STACK_SIZE, SIGCHLD, cmd);
    if (child == -1)return -1;
    if (waitpid(child, NULL, 0) == -1) return -1;
    return 0;
}

//コマンドを実行する関数1(slirp4netnsを実行用)
pid_t exec_command1(void *cmd) {
    char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) return -1;
    pid_t child = clone((int (*)(void *)) exec_command_child, stack + STACK_SIZE, SIGCHLD, cmd);
    if (child == -1)return -1;
    return child;
}

//chroot_dirしてinit実行
int isolated_child(isolated_child_args_t *args){
    char buf[1];
    if(read(args->fd[0], buf, 1) == -1) return -1;      //親プロセスが準備している間待つようにする
    if(chroot_dir(SYSROOT_DIR) == -1) return -1;
    exec_command("source /etc/profile");
    exec_command("mount -t proc proc /proc");
    exec_command("mount -t sysfs sysfs /sys");
    exec_command("set -m");
    char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);
    if (stack == MAP_FAILED) return -1;
    pid_t child = clone((int (*)(void *)) exec_command_child, stack + STACK_SIZE, SIGCHLD, "/bin/bash --login");
    if (child == -1)return -1;
    if (waitpid(child, NULL, 0) == -1) return -1;
    exec_command("umount /proc");
    exec_command("umount /sys");
}

//unshare -r みたいなやつを実行
int exec_fake_root(pid_t child){
    char cmd[STR_BUF_SIZE];
    snprintf(cmd, STR_BUF_SIZE, "echo \"0 $(id -u) 1\" > /proc/%d/uid_map", child);
    exec_command(cmd);

    snprintf(cmd, STR_BUF_SIZE, "echo \"deny\" > /proc/%d/setgroups", child);
    exec_command(cmd);

    snprintf(cmd, STR_BUF_SIZE, "echo \"0 $(id -g) 1\" > /proc/%d/gid_map", child);
    exec_command(cmd);

}

//slirp4netnsを実行
int exec_slirp4netns(pid_t child){
    char cmd[STR_BUF_SIZE];
    snprintf(cmd, STR_BUF_SIZE, "./slirp4netns --configure --mtu=65520 --disable-host-loopback %d tap0", child);
    
    return exec_command1(cmd);
}

//slirp4netnsのpidを消す
int kill_slirp4netns(pid_t child){
    char cmd[STR_BUF_SIZE];
    snprintf(cmd, STR_BUF_SIZE, "kill -9 %d", child);

    exec_command(cmd);

}

// 子プロセスを作成する
int start_child() {
    isolated_child_args_t args;

    if(pipe(args.fd) == -1) return -1;  //親プロセスが準備している間待つようにする

    char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, 
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK, -1, 0);

    if(stack == MAP_FAILED) return -1;

    pid_t child = clone((int (*)(void *)) isolated_child, stack + STACK_SIZE,
         SIGCHLD | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC, &args);

    if(child == -1) return -1;

    if(exec_fake_root(child) == -1) return-1;    //unshare -r みたいなやつを実行

    pid_t slirp4_pid = exec_slirp4netns(child); //slirp4netnsを実行
    if(slirp4_pid == -1) return -1;
    
    if(write(args.fd[1], "\0", 1) == -1) return-1;   //親プロセスが準備している間待つようにする


    if(waitpid(child, NULL, 0) == -1) return -1;

    if(kill_slirp4netns(slirp4_pid) == -1 ) return -1;  //slirp4netnsのpidを消す

    return 0;
}

int main(){
    return start_child();
}
