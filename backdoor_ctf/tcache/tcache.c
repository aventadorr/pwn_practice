// gcc tcache.c -o data_bank
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include <malloc.h>

void * table[8];
int size[8];
int count=5;

int get_inp(char *buffer, int size) {
    int retval = read(0, buffer, size);
    if (retval == -1)
        exit(0);
    if ( buffer[retval-1] == '\n')
        buffer[retval-1] = '\0';
    return retval-1;
}

int get_int() {
    char buffer[32];
    get_inp(buffer, 32);
    return atoi(buffer);
}

int  printmenu(){
    puts("1) Add note\n2) Edit note\n3) Free note\n4) View note\n5) Exit");
    printf(">> ");
    return get_int();
}

void add(){
    int idx;
    puts("Note index:");
    idx=get_int();
    while(idx >= 0 && idx < 8){
        if(table[idx] != NULL){
            puts("This note is occupied\n");
            return;
        }
        puts("Note size:");
        size[idx]=get_int();
        if(size[idx] < 0x00 || size[idx] > 0x200)
            puts("Invalid size");

        else{
            table[idx]=malloc(size[idx]);
            if(!table[idx]){
                exit(0);
            }
            puts("Note data:");
            get_inp(table[idx],size[idx]);
            return;
        }
    }
}


void edit(){
    int idx;
    puts("Note index:");
    idx=get_int();
    while(idx >= 0 && idx < 8){
        if(table[idx] == NULL){
            puts("This Note is empty\n");
            return;
        }
        puts("Please update the data:");
        int val=get_inp(table[idx],size[idx]);
        if(val)
            puts("update successful\n");
        else
            puts("update unsuccessful");
        return;
    }
}


void delete(){
    int idx;
    puts("Note index:");
    idx=get_int();
    while(idx >= 0 && idx < 8){
        if(table[idx] ==
            puts("This Note is empty");
            return;
        }
        if(count--){
            free(table[idx]);
            puts("done");
            return;
        }
        else{
            puts("Sorry no more removal\n");
            exit(0);
        }

    }
}

void view(){
    int idx;
    puts("Note index:");
    idx=get_int();
    while(idx >= 0 && idx < 8){
        if(table[idx] == NULL){
            puts("This Note is empty");
            return;
        }
        printf("Your Note :%s\n\n",(char*)table[idx]);
        return;
    }
}

int main(){
    alarm(60);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("----------BABYTCACHE----------");
    do {
        switch(printmenu()) {
            case 1: add(); break;
            case 2: edit(); break;
            case 3: delete(); break;
            case 4: view(); break;
            case 5: exit(0);
            default: puts("Invalid"); break;
        }
    } while(1);
    return 0;
}
