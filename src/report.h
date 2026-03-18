#ifndef REPORT_H
#define REPORT_H

#include "config.h"
#include "passive.h"

#include <stddef.h>

int write_csv_report(const char *path,
                     const host_record_list_t *records,
                     char *errbuf,
                     size_t errbuf_size);

#endif
