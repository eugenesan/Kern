/*
 * Copy the loaded wallet to a SeedKeeper card.
 *
 * The card stores the BIP-39 Masterseed: the seed, the entropy and the
 * passphrase, so "Load Mnemonic -> From SeedKeeper" finds the same wallet
 * again.  The passphrase is asked for and then checked against the loaded
 * wallet by comparing the master key fingerprint, so a wrong passphrase
 * fails instead of writing a different wallet to the card.
 */

#ifndef SEEDKEEPER_BACKUP_H
#define SEEDKEEPER_BACKUP_H

#include <lvgl.h>

/* Creates the flow.  The result is shown on the card page; the back arrow
 * returns to the caller. */
void seedkeeper_backup_page_create(lv_obj_t *parent, void (*return_cb)(void));
void seedkeeper_backup_page_show(void);
void seedkeeper_backup_page_hide(void);
void seedkeeper_backup_page_destroy(void);

#endif /* SEEDKEEPER_BACKUP_H */
