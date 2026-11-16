/*
 * Copy the loaded wallet to a SeedKeeper card.
 *
 * See seedkeeper_backup.h for the shape of the flow.
 */

#include "seedkeeper_backup.h"

#include "../passphrase.h"
#include "../../core/key.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../../utils/session_cleanup.h"
#include "seedkeeper_page.h"
#include <kern_wally.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENTROPY 64
#define DEFAULT_LABEL "kern"

static void (*return_callback)(void) = NULL;

static ui_text_input_t label_input = {0};
static char secret_label[SEEDKEEPER_MAX_LABEL + 1];
static char secret_passphrase[256];
static char stored_id[8];

static void return_from_passphrase_cb(void);
static void passphrase_ready_cb(const char *passphrase);
static int step_reopen(seedkeeper_card_t *c, void *ctx, char *err,
                       size_t err_cap);
static void done_reopen(void *ctx);
static int step_write(seedkeeper_card_t *c, void *ctx, char *err,
                      size_t err_cap);
static int step_import(seedkeeper_card_t *c, void *ctx, char *err,
                       size_t err_cap);
static void done_import(void *ctx);

/* --- the label ---------------------------------------------------------- */

static void label_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(label_input.textarea);
  snprintf(secret_label, sizeof(secret_label), "%s", text ? text : "");
  if (!secret_label[0])
    snprintf(secret_label, sizeof(secret_label), "%s", DEFAULT_LABEL);
  ui_secure_clear_textarea(label_input.textarea);
  ui_text_input_hide(&label_input);
  passphrase_page_create(lv_screen_active(), return_from_passphrase_cb,
                          passphrase_ready_cb);
  passphrase_page_show();
}

static void show_label_input(void) {
  if (!label_input.textarea)
    ui_text_input_create(&label_input, seedkeeper_page_container(), "Label",
                         false, label_ready_cb);
  ui_text_input_show(&label_input);
}

/* --- the passphrase ----------------------------------------------------- */

static void return_from_passphrase_cb(void) {
  passphrase_page_destroy();
  seedkeeper_page_show();
}

static void passphrase_ready_cb(const char *passphrase) {
  snprintf(secret_passphrase, sizeof(secret_passphrase), "%s",
           passphrase ? passphrase : "");
  passphrase_page_destroy();
  /* The label and the passphrase are in hand; now ask for the card.  The
   * session that was open while the user typed is long gone, and a card
   * command sent into it lands on the card manager instead of the
   * applet. */
  seedkeeper_page_run("Tap the card... (back arrow cancels)", step_reopen, false,
                       done_reopen, NULL);
}

/* --- the card work ------------------------------------------------------ */

/* The fingerprint of the master key that a seed derives, used to check
 * that the passphrase belongs to the wallet that is loaded. */
static bool seed_fingerprint(const uint8_t *seed, size_t seed_len,
                              uint8_t out[BIP32_KEY_FINGERPRINT_LEN]) {
  struct ext_key *master = NULL;
  bool ok = false;

  if (kern_bip32_key_from_seed_alloc(seed, seed_len, BIP32_VER_MAIN_PRIVATE, 0,
                                     &master) != WALLY_OK)
    return false;
  if (bip32_key_get_fingerprint(master, out, BIP32_KEY_FINGERPRINT_LEN) == 0)
    ok = true;
  bip32_key_free(master);
  return ok;
}

/* Runs on the worker task.  Brings the card back and logs in again. */
static int step_reopen(seedkeeper_card_t *c, void *ctx, char *err,
                       size_t err_cap) {
  (void)ctx;
  return seedkeeper_card_relogin(c, err, err_cap);
}

/* Runs on the UI thread. */
static void done_reopen(void *ctx) {
  (void)ctx;
  seedkeeper_page_run("Hold the card... writing", step_write, false,
                       done_import, NULL);
}

/* The write, and its retry.  The first call uses the session the tap just
 * opened; a retry after the link dropped has to bring the card back
 * first, and the user is asked for it again. */
static int step_write(seedkeeper_card_t *c, void *ctx, char *err,
                      size_t err_cap) {
  int rc;

  if (!c->logged_in && seedkeeper_card_relogin(c, err, err_cap) != 0)
    return -1;
  rc = step_import(c, ctx, err, err_cap);
  if (rc != 0 && (c->sk.last_sw == 0 || c->sk.last_sw == 0x6E00 ||
                  c->sk.last_sw == 0x6D00))
    c->logged_in = 0;
  return rc;
}

/* Runs on the worker task. */
static int step_import(seedkeeper_card_t *c, void *ctx, char *err,
                        size_t err_cap) {
  char *mnemonic = NULL;
  uint8_t entropy[MAX_ENTROPY];
  size_t entropy_len = sizeof(entropy);
  uint8_t seed[64];
  uint8_t payload[512];
  size_t payload_len = 0;
  uint8_t want_fp[BIP32_KEY_FINGERPRINT_LEN];
  uint8_t got_fp[BIP32_KEY_FINGERPRINT_LEN];
  uint16_t id = 0;
  uint8_t fingerprint[SEEDKEEPER_FINGERPRINT_SIZE];
  int rc;

  (void)ctx;

  if (!key_get_mnemonic(&mnemonic) || !mnemonic) {
    snprintf(err, err_cap, "No wallet is loaded");
    return -1;
  }
  if (kern_bip39_mnemonic_to_bytes(NULL, mnemonic, entropy, sizeof(entropy),
                                   &entropy_len) != WALLY_OK) {
    SECURE_FREE_STRING(mnemonic);
    snprintf(err, err_cap, "Could not read the wallet's entropy");
    return -1;
  }
  if (kern_bip39_mnemonic_to_seed512(mnemonic, secret_passphrase, seed,
                                      sizeof(seed)) != WALLY_OK) {
    SECURE_FREE_STRING(mnemonic);
    snprintf(err, err_cap, "Could not derive the seed");
    return -1;
  }
  SECURE_FREE_STRING(mnemonic);

  /* The card's copy has to be the same wallet as the one that is loaded,
   * so check the passphrase before writing anything. */
  if (!key_get_fingerprint(want_fp) ||
      !seed_fingerprint(seed, sizeof(seed), got_fp) ||
      memcmp(want_fp, got_fp, sizeof(want_fp)) != 0) {
    memset(seed, 0, sizeof(seed));
    snprintf(err, err_cap,
             "The passphrase does not match the loaded wallet");
    return -1;
  }

  rc = seedkeeper_pack_bip39(seed, sizeof(seed), entropy, entropy_len,
                             secret_passphrase, payload, sizeof(payload),
                             &payload_len);
  memset(seed, 0, sizeof(seed));
  memset(entropy, 0, sizeof(entropy));
  if (rc != 0) {
    snprintf(err, err_cap, "Could not pack the secret");
    return -1;
  }

  rc = seedkeeper_import_secret(&c->sk, SEEDKEEPER_TYPE_MASTERSEED,
                                 SEEDKEEPER_SUBTYPE_BIP39, secret_label, payload,
                                 payload_len, &id, fingerprint);
  memset(payload, 0, sizeof(payload));
  if (rc != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  seedkeeper_page_log("kern-nexus seedkeeper: stored secret %04x\n", id);
  snprintf(stored_id, sizeof(stored_id), "%04x", id);
  return 0;
}

static void done_import(void *ctx) {
  char text[160];
  (void)ctx;
  snprintf(text, sizeof(text),
           "Saved on the card as secret %s.\n\nLoad it again with\nLoad Mnemonic "
           "-> From SeedKeeper.",
           stored_id);
  seedkeeper_page_hide_error();
  seedkeeper_page_text(text);
}

/* --- lifecycle ---------------------------------------------------------- */

static void card_return_cb(void) {
  void (*callback)(void) = return_callback;

  seedkeeper_backup_page_destroy();
  if (callback)
    callback();
}

static void card_opened(void) {
  /* Name the secret first, then ask for the passphrase the card will
   * store next to the seed. */
  show_label_input();
}

void seedkeeper_backup_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(seedkeeper_backup_page_destroy);
  (void)parent;
  return_callback = return_cb;

  snprintf(secret_label, sizeof(secret_label), "%s", DEFAULT_LABEL);
  secret_passphrase[0] = '\0';
  stored_id[0] = '\0';

  seedkeeper_page_create_deferred(lv_screen_active(), "Back Up to Card",
                                   card_return_cb, card_opened);
}

void seedkeeper_backup_page_show(void) { seedkeeper_page_show(); }

void seedkeeper_backup_page_hide(void) { seedkeeper_page_hide(); }

void seedkeeper_backup_page_destroy(void) {
  session_cleanup_unregister(seedkeeper_backup_page_destroy);
  if (label_input.textarea)
    ui_text_input_destroy(&label_input);
  passphrase_page_destroy();
  seedkeeper_page_destroy();
  memset(secret_passphrase, 0, sizeof(secret_passphrase));
  secret_label[0] = '\0';
  stored_id[0] = '\0';
  return_callback = NULL;
}
