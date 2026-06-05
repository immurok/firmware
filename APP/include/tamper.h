/*
 * immurok Tamper Flag for CH592F
 * Persists a "case_opened" flag in DataFlash (0x6F00, last page of block 6),
 * survives the wipe of keystore/security blocks (0x0000-0x5FFF) and BLE SNV
 * (0x7000). Page 0 of block 6 (0x6000) is the OTA ImageFlag — left untouched.
 */
#ifndef IMMUROK_TAMPER_H
#define IMMUROK_TAMPER_H

#include <stdbool.h>

// Returns true if case_opened flag is currently set (tamper / interrupted wipe).
bool tamper_is_flagged(void);

// Set the flag (transaction begin, before wiping).
void tamper_set_flag(void);

// Clear the flag (transaction end, after a successful wipe).
void tamper_clear_flag(void);

#endif // IMMUROK_TAMPER_H
