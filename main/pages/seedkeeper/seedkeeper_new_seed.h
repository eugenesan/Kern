/*
 * New seed from a SeedKeeper card.
 *
 * The card generates the entropy, the device turns it into a BIP-39
 * mnemonic, and the card keeps the BIP-39 Masterseed so the same wallet
 * can be loaded again later.
 */

#ifndef SEEDKEEPER_NEW_SEED_H
#define SEEDKEEPER_NEW_SEED_H

#include <lvgl.h>

/* Creates the flow.  `success_cb` runs once the wallet is loaded. */
void seedkeeper_new_seed_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                     void (*success_cb)(void));
void seedkeeper_new_seed_page_show(void);
void seedkeeper_new_seed_page_hide(void);
void seedkeeper_new_seed_page_destroy(void);

#endif /* SEEDKEEPER_NEW_SEED_H */
