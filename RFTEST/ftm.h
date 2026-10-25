#ifndef FTM_H
#define FTM_H

#include <stdint.h>

/* Initialize the RF test subsystem (configure default RF, register TMOS task,
 * set echo default on). Call after BLE stack init (CH59x_BLEInit/HAL_Init/RF_RoleInit). */
void ftm_init(void);

/* Process one complete command line (without trailing \r\n). Called by UART line assembler. */
void ftm_on_line(const char *line);

/* Print one line to the command port (UART1), appends \r\n. Used internally and by main for banner. */
void ftm_puts(const char *s);

#endif /* FTM_H */
