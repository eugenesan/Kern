/*
 * Passphrase Page Header
 * Allows user to enter and confirm a BIP39 passphrase
 */

#ifndef PASSPHRASE_H
#define PASSPHRASE_H

#include <lvgl.h>

/**
 * Callback function type for passphrase confirmation
 * @param passphrase The confirmed passphrase (caller must copy if needed)
 */
typedef void (*passphrase_success_callback_t)(const char *passphrase);

/**
 * @brief Create the passphrase entry page
 *
 * @param parent Parent LVGL object where the page will be created
 * @param return_cb Callback function to call when returning to previous page
 * @param success_cb Callback function called with confirmed passphrase
 */
void passphrase_page_create(lv_obj_t *parent, void (*return_cb)(void),
                            passphrase_success_callback_t success_cb);

/* Same page, but the fingerprint preview is derived from a mnemonic that is
 * being loaded rather than from the key currently in memory.  Used by the
 * load flows before key_load_from_mnemonic(). */
void passphrase_page_create_for_mnemonic(
    lv_obj_t *parent, const char *mnemonic, void (*return_cb)(void),
    passphrase_success_callback_t success_cb);

/**
 * @brief Show the passphrase page
 */
void passphrase_page_show(void);

/**
 * @brief Hide the passphrase page
 */
void passphrase_page_hide(void);

/**
 * @brief Destroy the passphrase page and free resources
 */
void passphrase_page_destroy(void);

#endif // PASSPHRASE_H
