#include "passphrase.h"
#include "../core/key.h"
#include "../ui/assets/icons.h"
#include "../ui/dialog.h"
#include "../ui/input_helpers.h"
#include "../ui/theme_widgets.h"
#include "../utils/secure_mem.h"
#include "../utils/session_cleanup.h"
#include "shared/text_input_scan.h"
#include <lvgl.h>
#include <stdio.h>

static lv_obj_t *passphrase_screen = NULL;
static ui_text_input_t text_input = {0};
static void (*return_callback)(void) = NULL;
static passphrase_success_callback_t success_callback = NULL;
/* When set, the fingerprint preview uses this mnemonic instead of the key
 * currently loaded (the load flows call us before loading it). */
static const char *preview_mnemonic = NULL;

static void back_confirm_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && return_callback)
    return_callback();
}

static void back_btn_cb(lv_event_t *e) {
  (void)e;
  dialog_show_confirm("Are you sure you want to go back?", back_confirm_cb,
                      NULL, DIALOG_STYLE_OVERLAY);
}

static void confirm_passphrase_cb(bool result, void *user_data) {
  (void)user_data;
  if (result && success_callback)
    success_callback(lv_textarea_get_text(text_input.textarea));
}

static void scan_key_cb(void *user_data) {
  (void)user_data;
  text_input_scan_cfg_t cfg = {&text_input, passphrase_page_hide,
                               passphrase_page_show, NULL};
  text_input_scan_start(&cfg);
}

static void keyboard_ready_cb(lv_event_t *e) {
  (void)e;

  const char *text = lv_textarea_get_text(text_input.textarea);
  const char *passphrase = (text && text[0] != '\0') ? text : NULL;

  /* No passphrase is the empty string in BIP39.  Do not ask the user to
   * confirm a passphrase that does not exist; just continue. */
  if (!passphrase) {
    if (success_callback)
      success_callback("");
    return;
  }

  // A typo looks like plausible dots either way; only the fingerprint it
  // derives makes it visible, without putting the secret on screen.
  char before_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  char after_hex[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];
  bool ok;
  if (preview_mnemonic) {
    ok = key_mnemonic_fingerprint_hex(preview_mnemonic, before_hex) &&
         key_mnemonic_passphrase_fingerprint_hex(preview_mnemonic, passphrase,
                                                after_hex);
  } else {
    char *mnemonic = NULL;
    ok = key_get_fingerprint_hex(before_hex) &&
         key_get_mnemonic(&mnemonic) &&
         key_mnemonic_passphrase_fingerprint_hex(mnemonic, passphrase,
                                                after_hex);
    SECURE_FREE_STRING(mnemonic);
  }
  if (!ok)
    return;

  lv_color32_t c = lv_color_to_32(highlight_color(), LV_OPA_COVER);
  uint32_t highlight = (c.red << 16) | (c.green << 8) | c.blue;

  char prompt[128];
  snprintf(prompt, sizeof(prompt),
           "Confirm passphrase?\n\n" ICON_FINGERPRINT " %s\n" LV_SYMBOL_DOWN
           "\n#%06X " ICON_FINGERPRINT " %s#",
           before_hex, (unsigned)highlight, after_hex);
  dialog_show_confirm(prompt, confirm_passphrase_cb, NULL,
                      DIALOG_STYLE_OVERLAY);
}

static void create_page(lv_obj_t *parent, void (*return_cb)(void),
                        passphrase_success_callback_t success_cb) {
  session_cleanup_register(passphrase_page_destroy);
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  // Screen
  passphrase_screen = theme_create_page_container(lv_screen_active());

  // Create title label
  theme_create_page_title(passphrase_screen, "Enter Passphrase");

  // Back button
  ui_create_back_button(passphrase_screen, back_btn_cb);

  // Text input (textarea + keyboard), masked with an eye toggle to reveal
  ui_text_input_create(&text_input, passphrase_screen, "passphrase", true,
                       keyboard_ready_cb);
  ui_text_input_enable_scan(&text_input, scan_key_cb, NULL);
}

void passphrase_page_create(lv_obj_t *parent, void (*return_cb)(void),
                            passphrase_success_callback_t success_cb) {
  preview_mnemonic = NULL;
  create_page(parent, return_cb, success_cb);
}

void passphrase_page_create_for_mnemonic(
    lv_obj_t *parent, const char *mnemonic, void (*return_cb)(void),
    passphrase_success_callback_t success_cb) {
  preview_mnemonic = mnemonic;
  create_page(parent, return_cb, success_cb);
}

void passphrase_page_show(void) {
  if (passphrase_screen)
    lv_obj_clear_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_clear_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_hide(void) {
  if (passphrase_screen)
    lv_obj_add_flag(passphrase_screen, LV_OBJ_FLAG_HIDDEN);
  if (text_input.keyboard)
    lv_obj_add_flag(text_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void passphrase_page_destroy(void) {
  session_cleanup_unregister(passphrase_page_destroy);
  ui_text_input_destroy(&text_input);
  if (passphrase_screen) {
    lv_obj_del(passphrase_screen);
    passphrase_screen = NULL;
  }
  return_callback = NULL;
  success_callback = NULL;
  preview_mnemonic = NULL;
}
