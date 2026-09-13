#include <stdint.h>
#include <stddef.h>
void *verz_create(const uint8_t *, size_t);
void verz_destroy(void *);
int32_t verz_adapters(void *, const uint8_t *, size_t);
int32_t verz_send(void *, uint16_t, uint32_t, uint16_t, const uint8_t *, size_t);
void verz_tick(void *);
void verz_mode(void *, int32_t);
size_t verz_receive(void *, uint8_t *, size_t);
size_t verz_status(void *, uint8_t *, size_t);
