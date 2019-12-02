#ifndef _COMMON_H
#define _COMMON_H

#include <stdlib.h>

typedef void *fido_dev_io_open_t(const char *);
typedef void  fido_dev_io_close_t(void *);
typedef int   fido_dev_io_read_t(void *, unsigned char *, size_t, int);
typedef int   fido_dev_io_write_t(void *, const unsigned char *, size_t);

typedef struct fido_dev_io {
	fido_dev_io_open_t  *open;
	fido_dev_io_close_t *close;
	fido_dev_io_read_t  *read;
	fido_dev_io_write_t *write;
} fido_dev_io_t;

typedef enum {
	FIDO_OPT_OMIT = 0, /* use authenticator's default */
	FIDO_OPT_FALSE,    /* explicitly set option to false */
	FIDO_OPT_TRUE,     /* explicitly set option to true */
} fido_opt_t;

#endif /* !_COMMON_H */
