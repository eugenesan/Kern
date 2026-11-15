#ifndef LOAD_SEEDKEEPER_H
#define LOAD_SEEDKEEPER_H

#include <lvgl.h>

/* Load a BIP39 mnemonic from a SeedKeeper card over the Nexus 5's NFC. */
void load_seedkeeper_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                 void (*success_cb)(void));
void load_seedkeeper_page_show(void);
void load_seedkeeper_page_hide(void);
void load_seedkeeper_page_destroy(void);

#endif
