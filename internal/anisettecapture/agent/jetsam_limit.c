#include <stdint.h>
#include <stdlib.h>

extern int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t bufferSize);

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    int pid = (int)strtol(argv[1], NULL, 10);
    if (pid <= 0) {
        return 2;
    }
    return memorystatus_control(6, pid, 0, NULL, 0) == 0 ? 0 : 1;
}
