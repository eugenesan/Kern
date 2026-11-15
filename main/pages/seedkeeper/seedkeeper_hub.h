/*
 * The SeedKeeper card menu: list the secrets, delete one, read the card's
 * status and see how much room is left.
 */

#ifndef SEEDKEEPER_HUB_H
#define SEEDKEEPER_HUB_H

#include <lvgl.h>

void seedkeeper_hub_page_create(lv_obj_t *parent, void (*return_cb)(void));
void seedkeeper_hub_page_show(void);
void seedkeeper_hub_page_hide(void);
void seedkeeper_hub_page_destroy(void);

#endif /* SEEDKEEPER_HUB_H */
