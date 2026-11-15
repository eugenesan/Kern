/*
 * New seed from a SeedKeeper card.
 *
 * The card is the entropy source: INS A0 makes it generate 32 random
 * bytes, which the device turns into a 24-word BIP-39 mnemonic.  The card
 * keeps a BIP-39 Masterseed of that mnemonic, so "Load Mnemonic -> From
 * SeedKeeper" finds the same wallet again.
 *
 * A generated seed carries no passphrase: the card's Masterseed is derived
 * from the entropy alone, and the device loads exactly what the card
 * stores.  A wallet that needs a passphrase is created elsewhere and copied
 * to the card with "Back Up -> To SeedKeeper".
 */

#include "seedkeeper_new_seed.h"

#include "../shared/key_confirmation.h"
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

#define SEED_BYTES 32 /* 256 bits of entropy -> 24 words */
#define RAW_LABEL "kern-entropy"
#define BIP39_LABEL "kern"
#define MAX_WORDS 24

static char *new_mnemonic = NULL;
static uint8_t new_entropy[SEED_BYTES];
static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;

/* The page that shows the generated words. */
static lv_obj_t *words_screen = NULL;

static void return_from_key_confirmation_cb(void);
static void success_from_key_confirmation_cb(void);

/* --- the generated words ------------------------------------------------ */

static void words_destroy(void) {
  if (words_screen) {
    lv_obj_del(words_screen);
    words_screen = NULL;
  }
}

static void words_back_cb(lv_event_t *e) {
  (void)e;
  /* Backing out abandons the whole flow: the seed was never loaded. */
  words_destroy();
  seedkeeper_new_seed_page_destroy();
  if (return_callback)
    return_callback();
}

static void words_continue_cb(lv_event_t *e) {
  (void)e;
  seedkeeper_page_log("kern-nexus newseed: words accepted\n");
  words_destroy();
  seedkeeper_page_hide();
  key_confirmation_page_create_passphrase(
      lv_screen_active(), return_from_key_confirmation_cb,
      success_from_key_confirmation_cb, new_mnemonic,
      new_mnemonic ? strlen(new_mnemonic) : 0, "", true);
  key_confirmation_page_show();
}

static void return_from_key_confirmation_cb(void) {
  seedkeeper_page_log("kern-nexus newseed: key confirmation returned\n");
  key_confirmation_page_destroy();
  words_destroy();
  seedkeeper_new_seed_page_destroy();
  if (return_callback)
    return_callback();
}

static void success_from_key_confirmation_cb(void) {
  seedkeeper_page_log("kern-nexus newseed: wallet loaded\n");
  key_confirmation_page_destroy();
  words_destroy();
  seedkeeper_new_seed_page_destroy();
  if (success_callback)
    success_callback();
}

/* Splits the mnemonic and lays the words out in a scrollable column. */
static void words_show(void) {
  lv_obj_t *list;
  char copy[512];
  char *word;
  size_t index = 0;

  words_destroy();
  words_screen = theme_create_page_container(lv_screen_active());
  if (!words_screen)
    return;
  theme_create_page_title(words_screen, "Your New Seed");
  ui_create_back_button(words_screen, words_back_cb);

  lv_obj_t *warn = lv_label_create(words_screen);
  lv_label_set_text(warn,
                    "Write these words down.\nAnyone with them can spend "
                    "your coins.");
  lv_label_set_long_mode(warn, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(warn, LV_PCT(80));
  lv_obj_set_style_text_align(warn, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(warn, theme_font_small(), 0);
  lv_obj_align(warn, LV_ALIGN_TOP_MID, 0, 80);

  list = lv_obj_create(words_screen);
  lv_obj_set_size(list, LV_PCT(85), LV_PCT(62));
  lv_obj_align(list, LV_ALIGN_CENTER, 0, 40);
  lv_obj_set_flex_flow(list, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_CENTER);
  lv_obj_set_style_pad_row(list, 4, 0);
  lv_obj_set_style_border_width(list, 0, 0);

  snprintf(copy, sizeof(copy), "%s", new_mnemonic ? new_mnemonic : "");
  word = strtok(copy, " ");
  while (word && index < MAX_WORDS) {
    char line[64];
    snprintf(line, sizeof(line), "%2u. %s", (unsigned)(index + 1), word);
    lv_obj_t *label = lv_label_create(list);
    lv_label_set_text(label, line);
    lv_obj_set_style_text_font(label, theme_font_medium(), 0);
    index++;
    word = strtok(NULL, " ");
  }
  secure_memzero(copy, sizeof(copy));

  lv_obj_t *btn = theme_create_button(words_screen, "Continue", true);
  lv_obj_align(btn, LV_ALIGN_BOTTOM_MID, 0, -40);
  lv_obj_add_event_cb(btn, words_continue_cb, LV_EVENT_CLICKED, NULL);
}

/* --- the card work ------------------------------------------------------ */

/* Runs on the worker task.  Generates the entropy on the card, exports it,
 * and stores the BIP-39 Masterseed back on the card. */
static int step_generate(seedkeeper_card_t *c, void *ctx, char *err,
                         size_t err_cap) {
  uint8_t secret[128];
  size_t secret_len = sizeof(secret);
  uint8_t seed[64];
  uint8_t payload[256];
  size_t payload_len = 0;
  uint16_t id = 0;
  uint16_t bip39_id = 0;
  uint8_t fingerprint[SEEDKEEPER_FINGERPRINT_SIZE];
  size_t entropy_len = 0;
  int rc;

  (void)ctx;

  rc = seedkeeper_generate_masterseed(&c->sk, SEED_BYTES, RAW_LABEL,
                                       SEEDKEEPER_EXPORT_PLAINTEXT_ALLOWED,
                                       &id, fingerprint);
  if (rc != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  seedkeeper_page_log("kern-nexus seedkeeper: generated raw secret %04x\n", id);

  secret_len = sizeof(secret);
  rc = seedkeeper_export_secret(&c->sk, id, secret, &secret_len);
  if (rc != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    seedkeeper_reset_secret(&c->sk, id);
    return -1;
  }
  rc = seedkeeper_plain_secret_bytes(secret, secret_len, new_entropy,
                                      sizeof(new_entropy), &entropy_len);
  memset(secret, 0, sizeof(secret));
  if (rc != 0 || entropy_len != SEED_BYTES) {
    snprintf(err, err_cap, "The card returned an unusable secret");
    memset(new_entropy, 0, sizeof(new_entropy));
    seedkeeper_reset_secret(&c->sk, id);
    return -1;
  }

  /* The entropy is in RAM now, so the raw secret can go: if anything
   * below fails, the card is left exactly as it was rather than holding a
   * half-finished copy. */
  if (seedkeeper_reset_secret(&c->sk, id) != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    memset(new_entropy, 0, sizeof(new_entropy));
    return -1;
  }

  SECURE_FREE_STRING(new_mnemonic);
  if (kern_bip39_mnemonic_from_bytes(NULL, new_entropy, SEED_BYTES,
                                     &new_mnemonic) != WALLY_OK ||
      !new_mnemonic) {
    snprintf(err, err_cap, "Could not encode the mnemonic");
    memset(new_entropy, 0, sizeof(new_entropy));
    return -1;
  }

  /* The card keeps the BIP-39 Masterseed, so the same wallet can be
   * loaded from the card later.  It carries no passphrase: the entropy
   * alone is the secret. */
  if (kern_bip39_mnemonic_to_seed512(new_mnemonic, NULL, seed,
                                      sizeof(seed)) != WALLY_OK) {
    snprintf(err, err_cap, "Could not derive the seed");
    memset(seed, 0, sizeof(seed));
    return -1;
  }
  rc = seedkeeper_pack_bip39(seed, sizeof(seed), new_entropy, SEED_BYTES, "",
                             payload, sizeof(payload), &payload_len);
  memset(seed, 0, sizeof(seed));
  if (rc != 0) {
    snprintf(err, err_cap, "Could not pack the secret");
    return -1;
  }
  rc = seedkeeper_import_secret(&c->sk, SEEDKEEPER_TYPE_MASTERSEED,
                                 SEEDKEEPER_SUBTYPE_BIP39, BIP39_LABEL, payload,
                                 payload_len, &bip39_id, fingerprint);
  memset(payload, 0, sizeof(payload));
  if (rc != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  seedkeeper_page_log("kern-nexus seedkeeper: stored bip39 secret %04x\n",
                      bip39_id);

  memset(new_entropy, 0, sizeof(new_entropy));
  return 0;
}

static void done_generate(void *ctx) {
  (void)ctx;
  seedkeeper_page_log("kern-nexus newseed: generated, showing words\n");
  words_show();
}

/* --- lifecycle ---------------------------------------------------------- */

static void card_return_cb(void) {
  seedkeeper_page_log("kern-nexus newseed: card page returned\n");
  seedkeeper_new_seed_page_destroy();
  if (return_callback)
    return_callback();
}

static void card_opened(void) {
  seedkeeper_page_run("Generating a seed on the card...", step_generate, false,
                       done_generate, NULL);
}

void seedkeeper_new_seed_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                     void (*success_cb)(void)) {
  session_cleanup_register(seedkeeper_new_seed_page_destroy);
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  SECURE_FREE_STRING(new_mnemonic);
  memset(new_entropy, 0, sizeof(new_entropy));

  seedkeeper_page_create(lv_screen_active(), "New Seed", card_return_cb,
                          card_opened);
}

void seedkeeper_new_seed_page_show(void) { seedkeeper_page_show(); }

void seedkeeper_new_seed_page_hide(void) { seedkeeper_page_hide(); }

void seedkeeper_new_seed_page_destroy(void) {
  session_cleanup_unregister(seedkeeper_new_seed_page_destroy);
  words_destroy();
  seedkeeper_page_destroy();
  SECURE_FREE_STRING(new_mnemonic);
  memset(new_entropy, 0, sizeof(new_entropy));
  return_callback = NULL;
  success_callback = NULL;
}
