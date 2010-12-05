#define _BSD_SOURCE
#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <errno.h>

char *device = "/dev/ttyUSB0";
FILE *fd_device_w;
FILE *fd_device_r;

/* mifare default keys */
char *keys[] = {
    "\xA0\xA1\xA2\xA3\xA4\xA5",
    "\xB0\xB1\xB2\xB3\xB4\xB5",
    "\xFF\xFF\xFF\xFF\xFF\xFF",
    "\xD3\xF7\xD3\xF7\xD3\xF7",
    "\x00\x00\xFF\x07\x80\x69",
    "\xFF\x88\x00\x09\x60\x00",
};

/* table of error strings that can be received from the RFID reader */
const char* errors[] = { /* {{{ */
    "succeeded",
    "no tag",
    "login successful",
    "login failed",
    "read failed",
    "write failed",
    "unable to read after writing",
    "collision",
    "not authenticated",
    "not a value block",
    "checksum error",
    "command code error",
    "unknown error"
}; /* }}} */

/* translate errorcode from RFID reader into offset in errors[] table */
int translate_errorcode(int e) { /* {{{ */
    if (e <= 0x06) return e;
    switch(e) {
        case 0x0A: return 0x07;
        case 0x0D: return 0x08;
        case 0xF0: return 0x09;
        case 0xF1: return 0x0A;
        default:   return 0x0B;
    }
} /* }}} */

/* return pointer to error string for RFID reader error code e */
const char *get_errstr(int e) { /* {{{ */
    return errors[translate_errorcode(e)];
} /* }}} */

/* dumps hex and ascii values of word w with length c */
void dump_word(char *w, unsigned int c) { /* {{{ */
    for (int i = 0; i < c; i++) {
        printf("%02hhX", w[i]);
    }
    printf(" |");
    for (int i = 0; i < c; i++) {
        if ((w[i] >= 0x21) && (w[i] <= 0x7E))
            printf("%c", w[i]);
        else
            printf(".");
    }
    printf("|");
};
/* }}} */

/* create command with length len from data */
char *command(char *data, unsigned char len) { /* {{{ */
    char *rv = (char *)malloc(sizeof(char) * (len + 3));
    rv[0] = 0xBA;
    rv[1] = len + 1;
    memcpy(&(rv[2]), data, len);
    rv[len + 2] = 0;
    for (int i = 0; i < len+2; i++) {
        rv[len + 2] ^= rv[i];
    }
    return rv;
}
/* }}} */

/* write command in data with length len (as created by (char *)(command(data, len))) to fd_device */
void write_cmd(char *data, unsigned char len) { /* {{{ */
    char *cmd = command(data, len);
    fwrite(cmd, len+3, sizeof(char), fd_device_w);
    fseek(fd_device_w, 0L, SEEK_CUR);
    free(cmd);
} /* }}} */

/* receive RFID reader data and store it in dst. dst must be a pointer to 256 bytes of memory
 * returns the number of bytes received
 */
int receive_data(char *dst) { /* {{{ */
    char tmp;
    fread(dst, 2, sizeof(char), fd_device_r);
    int len = dst[1];
    for (int i = 0; i < len && i < (256 - 2); i++) {
        fread(&tmp, 1, sizeof(char), fd_device_r);
        dst[i + 2] = tmp;
    }
    return len + 2;
}
/* }}} */
 
/* read 16 bytes of data from block `idx' into dst
 * return value: 16 on success (length of data written into dst)
 *             -err on failure
 */
int read_block(unsigned char idx, char *dst) { /* {{{ */
    char *tmp;

    tmp    = (char *)malloc(sizeof(char) * 2);
    tmp[0] = 0x03; /* 0x03 = read data block */
    tmp[1] = idx;
    write_cmd(tmp, 2);
    free(tmp);
    
    tmp = (char *)malloc(sizeof(char) * 256);
    int len = receive_data(tmp);
    int err = tmp[3];

    if (err != 0x00) { /* an error occured */
        free(tmp);
        return -err;
    }

    memcpy(dst, &(tmp[4]), 16);
    free(tmp);

    return len - 5;
}
/* }}} */

/* write 16 bytes of data from buffer src into block idx
 * return value: 16 on success (data written into block idx is also stored in src)
 *             -err on failure
 */
int write_block(unsigned char idx, char *src) { /* {{{ */
    char *tmp;

    tmp = (char *) malloc(sizeof(char) * 18);
    tmp[0] = 0x04;
    tmp[1] = idx;
    memcpy(&(tmp[2]), src, 16);
    write_cmd(tmp, 18);
    free(tmp);

    tmp = (char *)malloc(sizeof(char) * 256);
    int len = receive_data(tmp);
    int err = tmp[3];

    if (err != 0x00) {
        free(tmp);
        return -err;
    }

    memcpy(src, &(tmp[4]), 16);
    free(tmp);

    return len - 5;
} /* }}} */

/* attempts an authentication to sector idx with the supplied key.
 * if key_type is 0xAA then KeyA is used, if it's 0xBB, KeyB is used.
 * All other values for key_type result in undefined behaviour!
 * return value: the error code returned by the RFID reader
 */
int login_sector(unsigned char idx, char key_type, char *key) { /* {{{ */
    char *tmp;
    
    tmp    = (char *)malloc(sizeof(char) * 9);
    tmp[0] = 0x02; /* 0x02 = sector login */
    tmp[1] = idx;
    tmp[2] = key_type;
    memcpy(&(tmp[3]), key, 6);
    write_cmd(tmp, 9);
    free(tmp);

    tmp = (char *)malloc(sizeof(char) * 256);
    int len = receive_data(tmp);
    int err = tmp[3];
    free(tmp);

    return err;
} /* }}} */

/* writes a new sector master key (i.e. KeyA) to sector idx. The sector needs to be logged into first.
 * return value: error code
 * *key contains the newly written key after execution
 */
int write_sector_key(unsigned char idx, char *key) { /* {{{ */
    char *tmp;

    tmp = (char *)malloc(sizeof(char) * 8);
    tmp[0] = 0x07; /* 0x07 = write sector key */
    tmp[1] = idx;
    memcpy(&(tmp[2]), key, 6);
    write_cmd(tmp, 8);
    free(tmp);

    tmp = (char *)malloc(sizeof(char) * 256);
    int len = receive_data(tmp);
    int err = tmp[3];
    memcpy(key, &(tmp[4]), 6);
    free(tmp);

    return err;
} /* }}} */

/* dumps all available data sectors 0x00 to 0x0F and blocks 0x00 to 0x03 for each sector
 * key #2 in mode 'A' is used
 */
void dump_data() { /* {{{ */
    printf("S#:B# data (hex)                       data (ASCII)\n");
    for(int sector = 0; sector <= 0x0F; sector++) {
        int err = login_sector(sector, 0xAA, keys[2]);
        if (err != 0x02) {
            printf("authentication error for sector %02hhX: %s\n", sector, get_errstr(err));
            continue;
        }
        for(int block = 0; block <= 0x03; block++) {
            char *data = (char *)malloc(sizeof(char) * 16);
            int len = read_block(block, data);
            printf("%02hhX:%02hhX ", sector, block);
            if (len < 0) {
                printf("error: %s", get_errstr(-len));
            } else {
                dump_word(data, len);
            }
            printf("\n");
            free(data);
        }
    }
}
/* }}} */

/* dumps and interprets all readable sector trailers */
void dump_sector_trailers() { /* {{{ */
    for(int sector = 0; sector <= 0x0F; sector++) {
        int err = login_sector(sector, 0xAA, keys[2]);
        if (err != 0x02) {
            printf("authentication error for sector %02hhX: %s\n", sector, get_errstr(err));
            continue;
        }
        char *data = (char *) malloc(sizeof(char) * 16);
        int len = read_block(0x03, data);
        if (len < 0) {
            free(data);
            continue;
        }
        char ac[4] = { data[6], data[7], data[8], data[9] };
        free(data);
        printf("%02hhX: %02hhX %02hhX %02hhX %02hhX\n", sector, ac[0], ac[1], ac[2], ac[3]);
        printf("  Data block 0x03: ");
        printf("C3=%d ", (ac[2] & (1 << 7)? 1: 0));
        printf("C2=%d ", (ac[2] & (1 << 3)? 1: 0));
        printf("C1=%d (sector trailer)\n", (ac[1] & (1 << 7)? 1: 0));

        printf("  Data block 0x02: ");
        printf("C3=%d ", (ac[2] & (1 << 6)? 1: 0));
        printf("C2=%d ", (ac[2] & (1 << 2)? 1: 0));
        printf("C1=%d\n", (ac[1] & (1 << 6)? 1: 0));

        printf("  Data block 0x01: ");
        printf("C3=%d ", (ac[2] & (1 << 5)? 1: 0));
        printf("C2=%d ", (ac[2] & (1 << 1)? 1: 0));
        printf("C1=%d\n", (ac[1] & (1 << 5)? 1: 0));

        printf("  Data block 0x00: ");
        printf("C3=%d ", (ac[2] & (1 << 4)? 1: 0));
        printf("C2=%d ", (ac[2] & (1 << 0)? 1: 0));
        printf("C1=%d\n", (ac[1] & (1 << 4)? 1: 0));
    }
} /* }}} */

int dump_info() { /* {{{ */
    unsigned char *data = (unsigned char *)malloc(sizeof(unsigned char) * 256);
    write_cmd("\x01", 1);
    int len = receive_data(data);
    printf("Card information:\n");

    printf("  Present: %02hhX (%s)\n", data[3], get_errstr(data[3]));
    if (data[3] != 0x00) return 0; /* no card present */

    printf("  Serial: ");
    for (unsigned char i = 0; i < len - 6; i++) {
        printf("%02hhX", data[i + 4]);
    }

    printf("\n  Type: %02hhX (", data[len - 2]);
    switch(data[len - 2]) {
        case 0x01:
            printf("Mifare Standard 1K");
            break;
        case 0x03:
            printf("Mifare Ultra Light");
            break;
        case 0x04:
            printf("Mifare Standard 4K");
            break;
        default:
            printf("unknown");
            break;
    }
    printf(")\n", data[len - 2]);
    free(data);
    return 1;
}
/* }}} */

/* print usage and exit */
void usage(char *name) { /* {{{ */
    printf("Usage: %s [-d tty] [-h]\n", name);
    printf("-d tty communicate with the RFID reader using device tty\n");
    printf("-h     show this help\n");
    exit(0);
}
/* }}} */

int main(int argc, char* argv[]) { /* {{{ */
    for(int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h")) usage(argv[0]);
        else if(!strcmp(argv[i], "-d")) {
            if (++i < argc) device = argv[i];
            else usage(argv[0]);
        }else usage(argv[0]);
    }

    if ((fd_device_r = fopen(device, "r")) == NULL) {
        fprintf(stderr, "couldn't open %s for reading: %s\n", device, strerror(errno));
        exit(1);
    }
    if (!isatty(fileno(fd_device_r))) {
        fprintf(stderr, "%s is not a tty!\n", device);
        exit(1);
    }
    if ((fd_device_w = fopen(device, "w")) == NULL) {
        fprintf(stderr, "couldn't open %s for writing: %s\n", device, strerror(errno));
        exit(1);
    }
    tcflush(fileno(fd_device_w), TCIOFLUSH);
    tcflush(fileno(fd_device_r), TCIOFLUSH);

    if (dump_info()) {
        printf("Dumping data:\n");
        dump_data();
        printf("Dumping sector trailers:\n");
        dump_sector_trailers();
    }

    return 0;
}
/* }}} */
