#ifndef WS2812_H
#define WS2812_H

#include <stdint.h>
#include "hardware_pins.h"

#if HAS_WS2812

void ws2812_init(void);
void ws2812_set_rgb(uint8_t r, uint8_t g, uint8_t b);

#endif
#endif
