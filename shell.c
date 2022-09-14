

/**
 * shell
 * CS 241 - Spring 2022
 */
#include "format.h"
#include "shell.h"
#include "vector.h"
#include "sstring.h"
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h> 

extern char *optarg;

static vector* processes;
static vector* history;
static char* history_file = NULL;
static FILE* input_file = NULL;
static int redirect = 0;


typedef struct process {
    char *command;
    pid_t pid;
} process;

int and_helper(char* cmd);
int or_helper(char* cmd);
int separator(char* cmd);

int redirect_output(char* cmd);
int redirect_append(char* cmd);

process* make_proc(pid_t pid, char* comm) {
    process* pointer = malloc(sizeof(process));
    pointer -> pid = pid;
    pointer -> command = malloc(sizeof(char) * (strlen(comm) + 1));
    strcpy(pointer -> command, comm);
    return pointer;
}

void done(int status) {
    if (history_file != NULL) {
        FILE *history_f = fopen(history_file, "w");

        for (size_t i = 0; i < vector_size(history); ++i) {
            fprintf(history_f, "%s\n", (char*)vector_get(history, i));
        }
        fclose(history_f);
    }
    if (history) {
        vector_destroy(history);
    }
    if (processes) {
        vector_destroy(processes);
    }
    if (input_file != stdin) {
        fclose(input_file);
    }
    exit(status);
}

char* handle_history(char*file) {
    FILE* fd = fopen(get_full_path(file), "r");

    if (fd) {
        char* bfr = NULL;
        size_t length = 0;

        while(getline(&bfr, &length, fd) != -1) {
            if (strlen(bfr) > 0 && bfr[strlen(bfr) - 1] == '\n') {
                bfr[strlen(bfr) - 1] = '\0';
                vector_push_back(history, bfr);
            }
        }

        free(bfr);
        fclose(fd);
        return get_full_path(file);
    } else {
        fd = fopen(file, "w");
    }


    fclose(fd);
    return get_full_path(file);
} 

size_t proc_index(pid_t pid) {
    ssize_t idx = -1;
    size_t i = 0;

    for (;i < vector_size(processes); i++) {
        process* pointer = vector_get(processes, i);
        if (pointer -> pid == pid) {
            idx = i;
            break;
        }
    }
    return idx;
}

void handle_signal(int sig_name) {
    if(sig_name == SIGINT) {

    } 
}

int cd(char* dir) {
    int result = chdir(dir);
    if (result != 0) {
        print_no_directory(dir);
        return 1;
    }
    return 0;
}

void ps_helper() {

    print_process_info_header();
    size_t i = 0;
    for (; i < vector_size(processes); i++) {

        process* proc = vector_get(processes, i);

        if(kill(proc -> pid,0) != -1){
            process_info info;

            info.command = proc -> command;
            info.pid = proc -> pid;
            
            char path[100];

            snprintf(path, sizeof(path), "/proc/%d/stat", proc->pid);
            FILE* fd = fopen(path, "r");
            unsigned long long starttime = 0;
            unsigned long time = 0;
            unsigned long long btime = 0;
            char time_str[20];

            if (fd) {
                char* bfr = NULL;
                size_t length;

                ssize_t bytes = getdelim( &bfr, &length, '\0', fd);
                if ( bytes != -1) {

                    sstring* s = cstr_to_sstring(bfr);

                    vector* nums_list = sstring_split(s, ' ');

                    long int nthreads = 0;
                    sscanf(vector_get(nums_list, 19), "%ld", &nthreads);
                    info.nthreads = nthreads;
                    
                    unsigned long int v_size = 0;
                    sscanf(vector_get(nums_list, 22), "%lu", &v_size);
                    info.vsize = v_size / 1024;

                    char state;
                    sscanf(vector_get(nums_list, 2), "%c", &state);
                    info.state = state;

                    unsigned long u_time = 0;
                    unsigned long s_time = 0;

                    sscanf(vector_get(nums_list, 14), "%lu", &s_time);
                    sscanf(vector_get(nums_list, 13), "%lu", &u_time);

                    time = u_time / sysconf(_SC_CLK_TCK) + s_time / sysconf(_SC_CLK_TCK);

                    unsigned long seconds = time % 60;
                    unsigned long mins = (time - seconds) / 60;
                    execution_time_to_string(time_str, 20, mins, seconds);
                    info.time_str = time_str;
                    
                    sscanf(vector_get(nums_list, 21), "%llu", &starttime);

                    vector_destroy(nums_list);
                    sstring_destroy(s);
                }
            }
            
            
            fclose(fd);


            
            FILE* fd2 = fopen("/proc/stat", "r");
            if (fd2) {
                char* buffer2 = NULL;
                size_t len;
                ssize_t bytes_read = getdelim( &buffer2, &len, '\0', fd2);
                if ( bytes_read != -1) {
                    sstring* s = cstr_to_sstring(buffer2);
                    // printf("%s\n", buffer);
                    vector* lines = sstring_split(s, '\n');
                    size_t i = 0;
                    for (; i < vector_size(lines); i++) {
                        if (strncmp("btime", vector_get(lines, i), 5) == 0) {
                            char str[10];
                            sscanf(vector_get(lines, i), "%s %llu", str, &btime);
                        }
                    }
                    vector_destroy(lines);
                    sstring_destroy(s);
                }
            }
            fclose(fd2);
            
            char start_str[20];
            time_t start_time_final = btime + (starttime / sysconf(_SC_CLK_TCK));
            time_struct_to_string(start_str, 20, localtime(&start_time_final));
            info.start_str = start_str;
            print_process_info(&info);  
        }
    }
}


int external_exec(char*cmd) {
    int bg = 0;
    pid_t pid = fork();

    process* proc = make_proc(pid, cmd);

    vector_push_back(processes, proc);
    sstring* s = cstr_to_sstring(cmd);
    vector* split = sstring_split(s, ' ');
    size_t size = vector_size(split);
    char* string_one = vector_get(split, 0);
    
    char* last_string = vector_get(split, size - 1);
    if (size >= 2) {

       if (strcmp(last_string, "&") == 0) {

            bg = 1;
            vector_set(split, size - 1, NULL); 
        }
    }

    char* arr [size + 1];

    size_t i = 0;

    for (;i < size; i++) {
        arr[i] = vector_get(split, i);
    }
    arr[size] = NULL;
    
    if (pid == -1) {
        print_fork_failed();
        done(1);
        return 1;
    }

    if (pid > 0) {
        if (!redirect) {
            print_command_executed(pid);
        }

        int status = 0;

        if (bg) {
            waitpid(pid, &status, WNOHANG);
        } else {
            pid_t pid_w = waitpid(pid, &status, 0);

            if (pid_w == -1) {
                print_wait_failed();
            } else if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) != 0) {
                    return 1;
                }
                fflush(stdout);
            } else if (WIFSIGNALED(status)) {

            }
            sstring_destroy(s);

            vector_destroy(split);

            return status;
        }

    } else if (pid == 0) {
        if (bg) {
            if (setpgid(getpid(), getpid()) == -1) {
                print_setpgid_failed();
                fflush(stdout);
                done(1);
            }
        }

        fflush(stdout);

        execvp(string_one, arr);

        // fail
        print_exec_failed(cmd);
        exit(1);
    }
    sstring_destroy(s);
    vector_destroy(split);
    return 1;
}
int exec(char* cmd, int logic) {
    if ((strstr(cmd, "&&")) != NULL) {
        vector_push_back(history, cmd);
        return and_helper(cmd);

    } else if ((strstr(cmd, "||")) != NULL) {
        vector_push_back(history, cmd);
        return or_helper(cmd);
    } else if ((strstr(cmd, ";")) != NULL) {
        vector_push_back(history, cmd);
        return separator(cmd);
    } else if ((strstr(cmd, ">>")) != NULL) {
        redirect = 1;
        vector_push_back(history, cmd);
        return redirect_append(cmd);
    } else if ((strstr(cmd, ">")) != NULL) {
        redirect = 1;
        vector_push_back(history, cmd);
        return redirect_output(cmd);
    } else if ((strstr(cmd, "<")) != NULL) {
        vector_push_back(history, cmd);
        return 0;
    }
    sstring* s = cstr_to_sstring(cmd);
    vector* split = sstring_split(s, ' ');
    int valid_cmd = 0;
    size_t size = vector_size(split);
    char* first_string = vector_get(split, 0);


    if (size != 0) {
        if(strcmp(first_string, "cd") == 0) {
            // cd

            if (size > 1) {
                valid_cmd = 1;
                if (!logic) {
                    vector_push_back(history, cmd);
                }

                int result = cd(vector_get(split, 1));

                sstring_destroy(s);
                vector_destroy(split);
                return result;
            }

        } else if (strcmp(first_string, "!history") == 0) {

            if (size == 1) {
                valid_cmd = 1;
                for (size_t i = 0; i < vector_size(history); i++) {
                    print_history_line(i, vector_get(history, i));
                }
                sstring_destroy(s);
                vector_destroy(split);
                return 0;

            }
        } else if (first_string[0] == '#') {
            if (size == 1 && strlen(first_string) != 1) {
                valid_cmd = 1;
                size_t index = atoi(first_string + 1);
                if (index < vector_size(history)) {
                    char* exec_ting = vector_get(history, index);
                    print_command(exec_ting);
                    sstring_destroy(s);

                    vector_destroy(split);

                    return exec(exec_ting, 0);
                } 

                print_invalid_index();
                sstring_destroy(s);
                vector_destroy(split);
                return 1;

            }
        } else if (first_string[0] == '!') {

            if (size >= 1) {
                valid_cmd = 1;
                char* pref = first_string + 1;
                for (size_t i = vector_size(history); i > 0; --i) {
                    char* another_cmd = vector_get(history, i - 1);
                    if (strncmp(another_cmd, pref, strlen(pref)) == 0) {
                        print_command(another_cmd);
                        sstring_destroy(s);
                        vector_destroy(split);
                        return exec(another_cmd, 0);
                    }


                }
                print_no_history_match();
                sstring_destroy(s);
                vector_destroy(split);
                return 1;
            }
        } else if (strcmp(first_string, "ps") == 0) {

            if (!logic) {
                vector_push_back(history, cmd);
            }
            if (size == 1) {
                valid_cmd = 1;
                ps_helper();
                return 0;
            }
        } else if (strcmp(first_string, "kill") == 0) {
            if (!logic) {
                vector_push_back(history, cmd);
            }

            if (size == 2) {
                valid_cmd = 1;
                pid_t target = atoi(vector_get(split, 1));
                ssize_t index = proc_index(target);
                if (index == -1) {
                    print_no_process_found(target);
                    sstring_destroy(s);
                    vector_destroy(split);
                    return 1;
                }
                kill(target, SIGKILL);
                print_killed_process(target, ((process*) vector_get(processes, index)) -> command);
                sstring_destroy(s);
                vector_destroy(split);
                return 0;
            }
        } else if (strcmp(first_string, "stop") == 0) {

            if (!logic) {
                vector_push_back(history, cmd);
            }
            if (size == 2) {
                valid_cmd = 1;
                pid_t target = atoi(vector_get(split, 1));
                ssize_t index = proc_index(target);
                if (index == -1) {
                    print_no_process_found(target);
                    sstring_destroy(s);
                    vector_destroy(split);
                    return 1;
                }


                kill(target, SIGSTOP);
                print_stopped_process(target, ((process*) vector_get(processes, index)) -> command);
                sstring_destroy(s);
                vector_destroy(split);
                
                return 0;
            }
        } else if (strcmp(first_string, "cont") == 0) {
            if (!logic) {
                vector_push_back(history, cmd);
            }
            if (size == 2) {
                valid_cmd = 1;
                pid_t target = atoi(vector_get(split, 1));
                ssize_t idx = proc_index(target);
                if (idx == -1) {
                    print_no_process_found(target);
                    sstring_destroy(s);
                    vector_destroy(split);
                    return 1;
                }

                kill(target, SIGCONT);
                print_continued_process(target, ((process*) vector_get(processes, idx)) -> command);
                sstring_destroy(s);
                vector_destroy(split);
                return 0;
            }
        } else if (strcmp(first_string, "exit") == 0) {

            if (size == 1) {
                valid_cmd = 1;
                done(0);
            }
        } else {

            if (!logic) {
                vector_push_back(history, cmd);
            }

            valid_cmd = 1;
            sstring_destroy(s);
            vector_destroy(split);
            fflush(stdout);
            return external_exec(cmd);
        }
       
    }

    if (valid_cmd == 0) {
        print_invalid_command(cmd);
    }
    sstring_destroy(s);
    vector_destroy(split);
    return 1;
}


int and_helper(char* cmd) {

    char* loc = strstr(cmd, "&&");
    size_t total_length = strlen(cmd);
    size_t first_cmd_length = loc - cmd;

    size_t second_cmd_length = total_length - (first_cmd_length + 3);
    char first_cmd [first_cmd_length];
    char second_cmd [second_cmd_length + 1];

    strncpy(first_cmd, cmd, first_cmd_length);
    strncpy(second_cmd, (loc + 3), second_cmd_length);

    first_cmd[first_cmd_length - 1] = '\0';
    second_cmd[second_cmd_length] = '\0';

    int status_one;
    if ((status_one = exec(first_cmd, 1)) == 0) {
        return exec(second_cmd, 1);
    }

    return 1;
}

int or_helper(char* cmd) {

    char* loc = strstr(cmd, "||");
    size_t total_length = strlen(cmd);
    size_t first_cmd_length = loc - cmd;

    size_t second_cmd_length = total_length - (first_cmd_length + 3);
    char first_cmd [first_cmd_length];
    char second_cmd [second_cmd_length + 1];
    strncpy(first_cmd, cmd, first_cmd_length);
    strncpy(second_cmd, (loc + 3), second_cmd_length);

    first_cmd[first_cmd_length - 1] = '\0';
    second_cmd[second_cmd_length] = '\0';

    int status_one;
    if ((status_one = exec(first_cmd, 1)) != 0) {
        return exec(second_cmd, 1);
    }
    return 0;
}

int separator(char* cmd) {

    char* loc = strstr(cmd, ";");

    size_t total_length = strlen(cmd);
    size_t first_cmd_length = loc - cmd;

    size_t second_cmd_length = total_length - (first_cmd_length + 2);
    char first_cmd [first_cmd_length + 1];
    char second_cmd [second_cmd_length + 1];

    strncpy(first_cmd, cmd, first_cmd_length);

    strncpy(second_cmd, (loc + 2), second_cmd_length);

    first_cmd[first_cmd_length] = '\0';
    second_cmd[second_cmd_length] = '\0';
    
    int result1 = exec(first_cmd, 1);
    int result2 = exec(second_cmd, 1);

    return result1 && result2;
}


int redirect_append(char* cmd) {
    char* loc = strstr(cmd, ">>");
    size_t total_length = strlen(cmd);
    size_t first_cmd_length = loc - cmd;

    size_t second_cmd_length = total_length - (first_cmd_length + 3);
    char first_cmd [first_cmd_length];
    char second_cmd [second_cmd_length + 1];

    strncpy(first_cmd, cmd, first_cmd_length);

    strncpy(second_cmd, (loc + 3), second_cmd_length);

    first_cmd[first_cmd_length - 1] = '\0';
    second_cmd[second_cmd_length] = '\0';
    FILE* fd = fopen(second_cmd, "a");

    int f_num = fileno(fd);
    int original = dup(fileno(stdout));
    fflush(stdout);

    dup2(f_num, fileno(stdout));

    exec(first_cmd, 1);
    fflush(stdout);
    close(f_num);
    dup2(original, fileno(stdout));


    redirect = 0;
    return 0;
}

int redirect_output(char* cmd) {
    char* loc = strstr(cmd, ">");
    size_t total_length = strlen(cmd);
    size_t first_cmd_length = loc - cmd;

    size_t second_cmd_length = total_length - (first_cmd_length + 2);
    char first_cmd [first_cmd_length];
    char second_cmd [second_cmd_length + 1];

    strncpy(first_cmd, cmd, first_cmd_length);
    strncpy(second_cmd, (loc + 2), second_cmd_length);

    first_cmd[first_cmd_length - 1] = '\0';
    second_cmd[second_cmd_length] = '\0';
    
    FILE* fd = fopen(second_cmd, "w");

    int fd_num = fileno(fd);
    int original = dup(fileno(stdout));
    fflush(stdout);
    dup2(fd_num, fileno(stdout));

    exec(first_cmd, 1);

    fflush(stdout);
    close(fd_num);
    dup2(original, fileno(stdout));

    redirect = 0;
    return 0;
}

int shell(int argc, char *argv[]) {
    // TODO: This is the entry point for your shell.

    //  input
    if (!(argc == 1 || argc == 3 || argc == 5)) {
        print_usage();
        exit(1);
    }


    signal(SIGINT, handle_signal);
    int pid = getpid();

    // create shell process and store in process vector
    process* shell =  make_proc(pid, argv[0]);

    processes = shallow_vector_create();
    vector_push_back(processes, shell);
    
    // history vector
    history = string_vector_create();


    char* cwd = malloc(256);

    input_file = stdin;

    if (getcwd(cwd, 256) == NULL) {
        done(1);
    }

    print_prompt(getcwd(cwd, 256), pid);

    int argument;
    while((argument = getopt(argc, argv, "f:h:")) != -1) {
        if (argument == 'h') {
            history_file = handle_history(optarg);

        } else if (argument == 'f') {

            FILE* scr = fopen(optarg, "r");
            if (scr == NULL) {
                print_script_file_error();
                done(1);
            }

            input_file = scr;
        } else {
            print_usage();
            done(1);
        }
    }


    char* bfr = NULL;
    size_t length = 0;
    while (getline(&bfr, &length, input_file) != -1) {
        int status;

        size_t i = 0;
        for (; i < vector_size(processes); i++) {
            process* p = vector_get(processes, i);
            waitpid(p -> pid, &status, WNOHANG); 
        }
        
        if (strcmp(bfr, "\n") == 0) {
           // do nothing
        } else {
            if (strlen(bfr) > 0 && bfr[strlen(bfr) - 1] == '\n') {
                bfr[strlen(bfr) -1] = '\0';
            }

            char* copy = malloc(strlen(bfr));
            strcpy(copy, bfr);
            exec(copy, 0);

        }

        if (getcwd(cwd, 256) == NULL) {
            done(1);
        }

        print_prompt(getcwd(cwd, 256), pid);
        fflush(stdout);
    }
    free(bfr);
    done(0);
    return 0;
}