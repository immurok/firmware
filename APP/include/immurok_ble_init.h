/*
 * immurok BLE init — runtime-selectable device BLE address.
 * See immurok_ble_init.c for why this exists instead of the SDK's
 * CH59x_BLEInit() / the BLE_MAC compile-time macro.
 */
#ifndef IMMUROK_BLE_INIT_H
#define IMMUROK_BLE_INIT_H

#include <stdint.h>
#include "immurok_slots.h"

/* Replacement for the SDK's CH59x_BLEInit(): identical body, except the
 * device address comes in as a parameter. */
void immurok_BLEInit(const uint8_t mac[6]);

/* Fill out_mac for the given host slot, starting from the chip's factory MAC.
 * Slot 1 = factory MAC unchanged (identical to shipped firmware). */
void immurok_ble_slot_mac(uint8_t slot, uint8_t out_mac[6]);

#endif // IMMUROK_BLE_INIT_H
