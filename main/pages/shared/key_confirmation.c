#include "key_confirmation.h"
#include "../passphrase.h"
#include "../../core/key.h"
#include "../../core/registry.h"
#include "../../core/secp_hardening.h"
#include "../../core/settings.h"
#include "../../core/wallet.h"
#include "../../qr/encoder.h"
#include "../../ui/assets/icons.h"
#include "../../ui/dialog.h"
#include "../../ui/oneshot.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../../utils/session_cleanup.h"
#include "descriptor_loader.h"
#include <lvgl.h>
#include <string.h>

#define LOADING_DELAY_MS 1000

static lv_obj_t *key_confirmation_screen = NULL;
static ui_oneshot_t loading_timer;
static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;
static char *mnemonic_content = NULL;
static char *confirmation_passphrase = NULL;
static char fingerprint_hex_cache[BIP32_KEY_FINGERPRINT_LEN * 2 + 1];

static void loading_timer_cb(lv_timer_t *timer) {
  (void)timer;
  wallet_network_t net = settings_get_network();
  const char *passphrase = (confirmation_passphrase &&
                            confirmation_passphrase[0])
                               ? confirmation_passphrase
                               : NULL;
  if (key_load_from_mnemonic(mnemonic_content, passphrase,
                             net == WALLET_NETWORK_TESTNET)) {
    if (!wallet_init(net)) {
      dialog_show_error_timeout("Failed to initialize wallet", return_callback,
                                0);
      return;
    }
    secp_blind_refresh();
    registry_init(net == WALLET_NETWORK_TESTNET);
    if (success_callback)
      success_callback();
    descriptor_loader_show_rejected_notice();
  } else {
    dialog_show_error_timeout("Failed to load key", return_callback, 0);
  }
}

static void anim_size_cb(void *var, int32_t value) {
  lv_obj_t *obj = (lv_obj_t *)var;
  lv_obj_set_size(obj, value, value);
}

static void start_reveal_anim(lv_obj_t *obj, int32_t target_size,
                              uint32_t duration, uint32_t delay) {
  lv_obj_set_size(obj, 0, 0);
  lv_anim_t anim;
  lv_anim_init(&anim);
  lv_anim_set_var(&anim, obj);
  lv_anim_set_exec_cb(&anim, anim_size_cb);
  lv_anim_set_values(&anim, 0, target_size);
  lv_anim_set_duration(&anim, duration);
  lv_anim_set_delay(&anim, delay);
  lv_anim_set_path_cb(&anim, lv_anim_path_ease_out);
  lv_anim_start(&anim);
}

static void create_ui(const char *fingerprint_hex) {
  key_confirmation_screen = lv_obj_create(lv_screen_active());
  lv_obj_set_size(key_confirmation_screen, LV_PCT(100), LV_PCT(100));
  theme_apply_screen(key_confirmation_screen);
  lv_obj_clear_flag(key_confirmation_screen, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *center = theme_create_flex_column(key_confirmation_screen);
  lv_obj_set_style_pad_row(center, 20, 0);
  lv_obj_align(center, LV_ALIGN_TOP_MID, 0, 0);

  lv_obj_t *fp_row = theme_create_flex_row(center);
  lv_obj_set_style_pad_column(fp_row, 8, 0);

  // Circular clip container for reveal animation
  lv_obj_t *icon_clip = lv_obj_create(fp_row);
  lv_obj_remove_style_all(icon_clip);
  lv_obj_set_style_radius(icon_clip, LV_RADIUS_CIRCLE, 0);
  lv_obj_add_flag(icon_clip, LV_OBJ_FLAG_OVERFLOW_VISIBLE);
  lv_obj_set_style_clip_corner(icon_clip, true, 0);

  lv_obj_t *icon = lv_label_create(icon_clip);
  lv_label_set_text(icon, ICON_FINGERPRINT_36);
  lv_obj_set_style_text_font(icon, theme_font_medium(), 0);
  lv_obj_set_style_text_color(icon, highlight_color(), 0);
  lv_obj_center(icon);

  // Start circular reveal animation
  start_reveal_anim(icon_clip, 36, 700, 150);

  lv_obj_t *fp_text = lv_label_create(fp_row);
  lv_label_set_text(fp_text, fingerprint_hex);
  lv_obj_set_style_text_font(fp_text, theme_font_medium(), 0);
  lv_obj_set_style_text_color(fp_text, highlight_color(), 0);

  ui_oneshot_start(&loading_timer, loading_timer_cb, LOADING_DELAY_MS);
}

static void set_passphrase(const char *passphrase) {
  SECURE_FREE_STRING(confirmation_passphrase);
  if (!passphrase)
    passphrase = "";
  size_t len = strlen(passphrase);
  confirmation_passphrase = malloc(len + 1);
  if (confirmation_passphrase)
    memcpy(confirmation_passphrase, passphrase, len + 1);
}

static void passphrase_cancel_cb(void) {
  void (*callback)(void) = return_callback;
  passphrase_page_destroy();
  key_confirmation_page_destroy();
  if (callback)
    callback();
}

static void passphrase_success_cb(const char *passphrase) {
  set_passphrase(passphrase);
  passphrase_page_destroy();
  create_ui(fingerprint_hex_cache);
}

static void create_common(lv_obj_t *parent, void (*return_cb)(void),
                          void (*success_cb)(void), const char *content,
                          size_t content_len, const char *passphrase,
                          bool passphrase_provided) {
  session_cleanup_register(key_confirmation_page_destroy);
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;

  SECURE_FREE_STRING(mnemonic_content);
  mnemonic_content = mnemonic_qr_to_mnemonic(content, content_len, NULL);
  if (!mnemonic_content) {
    dialog_show_error_timeout(
        "Could not read mnemonic: invalid data or insufficient internal RAM",
        return_callback, 0);
    return;
  }

  if (!key_mnemonic_fingerprint_hex(mnemonic_content, fingerprint_hex_cache)) {
    dialog_show_error_timeout("Failed to process mnemonic", return_callback, 0);
    return;
  }

  if (passphrase_provided) {
    set_passphrase(passphrase);
    create_ui(fingerprint_hex_cache);
  } else {
    /* A source without a passphrase still needs the option: the page accepts
     * an empty entry, which means "no passphrase". */
    passphrase_page_create_for_mnemonic(lv_screen_active(), mnemonic_content,
                                        passphrase_cancel_cb,
                                        passphrase_success_cb);
    passphrase_page_show();
  }
}

void key_confirmation_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                  void (*success_cb)(void), const char *content,
                                  size_t content_len) {
  create_common(parent, return_cb, success_cb, content, content_len, NULL,
                false);
}

void key_confirmation_page_create_passphrase(
    lv_obj_t *parent, void (*return_cb)(void), void (*success_cb)(void),
    const char *content, size_t content_len, const char *passphrase,
    bool passphrase_provided) {
  create_common(parent, return_cb, success_cb, content, content_len, passphrase,
                passphrase_provided);
}

void key_confirmation_page_show(void) {
  if (key_confirmation_screen)
    lv_obj_clear_flag(key_confirmation_screen, LV_OBJ_FLAG_HIDDEN);
}

void key_confirmation_page_hide(void) {
  if (key_confirmation_screen)
    lv_obj_add_flag(key_confirmation_screen, LV_OBJ_FLAG_HIDDEN);
}

void key_confirmation_page_destroy(void) {
  session_cleanup_unregister(key_confirmation_page_destroy);
  ui_oneshot_cancel(&loading_timer);
  passphrase_page_destroy();
  SECURE_FREE_STRING(mnemonic_content);
  SECURE_FREE_STRING(confirmation_passphrase);
  if (key_confirmation_screen) {
    lv_obj_del(key_confirmation_screen);
    key_confirmation_screen = NULL;
  }
  return_callback = NULL;
  success_callback = NULL;
}
