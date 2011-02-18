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
enum {
    MODE_NOTHING = 0x0,
    MODE_SECTORS = 0x1,
    MODE_DATA    = 0x1 << 1,
    MODE_BRUTE   = 0x1 << 2
};
/* ID of default key */
int keyid = 2;
/* mifare default keys */
#define NUMKEYS 11
char *keys[NUMKEYS] = {
    "\x00\x00\x00\x00\x00\x00",
    "\x00\x00\xFF\x07\x80\x69",
    "\x1A\x98\x2C\x7E\x45\x9A",
    "\x4D\x3A\x99\xC3\x51\xDD",
    "\xA0\xA1\xA2\xA3\xA4\xA5",
    "\xAA\xBB\xCC\xDD\xEE\xFF",
    "\xAB\xCD\xEF\x01\x23\x45",
    "\xB0\xB1\xB2\xB3\xB4\xB5",
    "\xD3\xF7\xD3\xF7\xD3\xF7",
    "\xFF\x88\x00\x09\x60\x00",
    "\xFF\xFF\xFF\xFF\xFF\xFF",
};

/* struct representing a card */
typedef enum {
    CARD_UNKNOWN = 0,
    CARD_MIFARE_1K,
    CARD_MIFARE_4K,
    CARD_MIFARE_ULTRA,
    CARD_DESFIRE
} card_type;

struct {
    card_type t;
} card;

/* returns the sector number for block `idx' */
int block_get_sector(int idx) { /* {{{ */
    return (int)(idx / 4);
} /* }}} */

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
    for(int block = 0; block <= 0x3F; block++) {
        if (block % 0x04 == 0) {
            int err = login_sector(block_get_sector(block), 0xAA, keys[keyid]);
            if (err != 0x02) {
                printf("could not authenticate to sector %02hhX: %s\n", block_get_sector(block), get_errstr(err));
                block += 3;
                continue;
            }
        }
        char *data = (char *)malloc(sizeof(char) * 16);
        int len = read_block(block, data);
        printf("%02hhX:%02hhX ", block_get_sector(block), block);
        dump_word(data, 16);
        if (len < 0) {
            printf(" (%02hhX: %s)", -len, get_errstr(-len));
        }
        printf("\n");
        free(data);
    }
}
/* }}} */

/* dumps and interprets all readable sector trailers */
void dump_sector_trailers() { /* {{{ */
    for(int sector = 0; sector <= 0x0F; sector++) {
        int err = login_sector(sector, 0xAA, keys[keyid]);
        if (err != 0x02) {
            printf("authentication error for sector %02hhX: %s\n", sector, get_errstr(err));
            continue;
        }
        char *data = (char *) malloc(sizeof(char) * 16);
        int len = read_block(sector * 0x03, data);
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

/* trys all known keys to access the sector in `brute_sector' */
int break_sector(short brute_sector) { /* {{{ */
    for(keyid = 0; keyid < NUMKEYS; keyid++) {
        int err = login_sector((unsigned char) brute_sector, 0xAA, keys[keyid]);
        if (err == 0x02) {
            printf("Key %d (", keyid);
            dump_word(keys[keyid], 6);
            printf(") opened sector %02hhX in mode 0xAA\n", brute_sector);
            return 1;
        }
        err = login_sector((unsigned char) brute_sector, 0xBB, keys[keyid]);
        if (err == 0x02) {
            printf("Key %d (", keyid);
            dump_word(keys[keyid], 6);
            printf(") opened sector %02hhX in mode 0xBB\n", brute_sector);
            return 1;
        }
    }
    printf("no key in the list of known keys could open sector %02hhX\n", brute_sector);
    return 0;
} /* }}} */

/* dumps card info
 * return value: 0x1 if card is present
 *               0x0 else
 */
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
            card.t = CARD_MIFARE_1K;
            break;
        case 0x03:
            printf("Mifare Ultra Light");
            card.t = CARD_MIFARE_ULTRA;
            break;
        case 0x04:
            printf("Mifare Standard 4K");
            card.t = CARD_MIFARE_4K;
            break;
        case 0x06:
            printf("EV1 / NXP DESfire");
            card.t = CARD_DESFIRE;
            break;
        default:
            printf("unknown");
            card.t = CARD_UNKNOWN;
            break;
    }
    printf(")\n", data[len - 2]);
    free(data);
    return 1;
}
/* }}} */

/* print usage and exit */
void usage(char *name) { /* {{{ */
    printf("Usage: %s [-d tty] [-K] [-k id] [-D] [-s] [-b id] [-h]\n", name);
    printf("-d tty communicate with the RFID reader using device tty\n");
    printf("-K     dump available default keys\n");
    printf("-k id  use key id\n");
    printf("-D     dump card data\n");
    printf("-s     dump sector trailer data\n");
    printf("-b id  try brute force to access sector #id\n");
    printf("-h     show this help\n");
    exit(0);
}
/* }}} */

/* dump available keys */
void dump_keys(void) { /* {{{ */
    printf("Dumping available default keys\n\n");
    for(keyid = 0; keyid < NUMKEYS; keyid++) {
        printf("% 3d: ", keyid);
        dump_word(keys[keyid], 6);
        printf("\n");
    }
    exit(0);
} /* }}} */

int main(int argc, char* argv[]) { /* {{{ */
    short brute_sector = 0x00;
    short mode = MODE_NOTHING;

    /* {{{ parameter parsing */
    for(int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h")) usage(argv[0]);
        else if(!strcmp(argv[i], "-D")) mode |= MODE_DATA;
        else if(!strcmp(argv[i], "-s")) mode |= MODE_SECTORS;
        else if(!strcmp(argv[i], "-K")) dump_keys();
        else if(!strcmp(argv[i], "-b")) {
            mode |= MODE_BRUTE;
            if (++i < argc) {
                brute_sector = atoi(argv[i]);
                if ((brute_sector < 0) || (brute_sector > 31)) {
                    printf("Invalid sector number %s!\n", argv[i]);
                    exit(0);
                }
            }else
                brute_sector = -1;
        }else if(!strcmp(argv[i], "-d")) {
            if (++i < argc) device = argv[i];
            else usage(argv[0]);
        }else if(!strcmp(argv[i], "-k")) {
            if (++i < argc) {
                keyid = atoi(argv[i]);
                if ((keyid < 0) || (keyid >= NUMKEYS)) {
                    printf("Unknown key %s!\n", argv[i]);
                    exit(0);
                }
            } else usage(argv[0]);
            printf("Using key #%d/%d: ", keyid, NUMKEYS);
            dump_word(keys[keyid], 6);
            printf("\n");
        }else usage(argv[0]);
    } /* }}} */

    /* {{{ tty acquisition */
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
    /* }}} */

    if (!dump_info()) {
        exit(0);
    }

    if ((card.t != CARD_MIFARE_1K) && (card.t != CARD_MIFARE_4K)) {
        /* we don't support anything else yet, mostly because of lack of tags to play with */
        exit(0);
    }

    if (mode & MODE_DATA) {
        printf("Dumping data:\n");
        dump_data();
    }
    if (mode & MODE_SECTORS) {
        printf("Dumping sector trailers:\n");
        dump_sector_trailers();
    }
    if (mode & MODE_BRUTE) {
        if (brute_sector != -1) {
            printf("Trying brute force access to sector %02hhX\n", brute_sector);
            break_sector(brute_sector);
        } else {
            short idx, max_idx = (card.t == CARD_MIFARE_4K) ? 0x1F : 0x0E;
            printf("Brute forcing access to all sectors\n");
            for (idx = 0; idx <= max_idx; idx++)
                break_sector(idx);
        }
    }

    return 0;
}
/* }}} */
