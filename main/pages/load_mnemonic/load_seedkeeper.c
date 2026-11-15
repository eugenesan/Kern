/*
 * Load a BIP39 mnemonic from a SeedKeeper card.
 *
 * The card is reached through the BCM2079x/NFC layer.  Bring-up can take up
 * to 30 s and every APDU blocks, so the card work runs on the shared worker
 * task and an LVGL timer polls it.  The UI thread never touches the NFC fd.
 *
 * Flow: hold card -> bring-up + SELECT -> PIN -> list headers -> export the
 * chosen Masterseed -> unpack the BIP39 payload -> key confirmation, which
 * asks for a passphrase only when the secret did not carry one.
 */

#include "load_seedkeeper.h"
#include "../shared/key_confirmation.h"
#include "../../core/key.h"
#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../../utils/session_cleanup.h"
#include "../../utils/worker_task.h"
#include "seedkeeper.h"
#include <kern_wally.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SECRETS 64
#define WORKER_STACK 12288

typedef enum {
  WORK_NONE,
  WORK_DISCOVER,
  WORK_LOGIN,
  WORK_EXPORT,
} work_kind_t;

static lv_obj_t *sk_screen = NULL;
static lv_obj_t *sk_menu_screen = NULL;
static ui_menu_t *sk_menu = NULL;
static ui_text_input_t pin_input = {0};
static lv_obj_t *progress_dialog = NULL;
static lv_timer_t *poll_timer = NULL;

static kern_nfc_t nfc = {.fd = -1};
static kern_seedkeeper_t sk;
static kern_seedkeeper_header_t headers[MAX_SECRETS];
static size_t header_count = 0;
static size_t selected_header = 0;
static char pin[SEEDKEEPER_PIN_MAX + 1];

static volatile bool work_done = false;
static work_kind_t work_kind = WORK_NONE;
static int work_rc = 0;
static char work_error[96];

static bool working = false;
static volatile bool cancel_requested = false;
static char *work_mnemonic = NULL;
static char work_passphrase[256];
static bool work_has_passphrase = false;

static void (*return_callback)(void) = NULL;
static void (*success_callback)(void) = NULL;

static int nfc_transmit(void *ctx, const uint8_t *apdu, size_t apdu_len,
                        uint8_t *resp, size_t *resp_len, uint8_t *sw1,
                        uint8_t *sw2) {
  return kern_nfc_transceive((kern_nfc_t *)ctx, apdu, apdu_len, resp, resp_len,
                             sw1, sw2);
}

static void klog(const char *fmt, ...) {
  int fd = open("/dev/kmsg", O_WRONLY);
  if (fd >= 0) {
    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
    close(fd);
  }
}

static void set_error(const char *text) {
  work_rc = -1;
  snprintf(work_error, sizeof(work_error), "%s", text);
}

static void show_progress(const char *title, const char *text) {
  if (progress_dialog)
    lv_obj_del(progress_dialog);
  progress_dialog = dialog_show_progress(title, text, DIALOG_STYLE_OVERLAY);
}

static void hide_progress(void) {
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
}

/* Runs on the worker task; never touches LVGL. */
static void card_work(void) {
  /* A selection uses the session opened by the PIN step.  Do not select the
   * applet again: that logs the card out and asks for the PIN a second time. */
  if (work_kind == WORK_EXPORT) {
    uint8_t secret[512];
    size_t secret_len = sizeof(secret);
    uint8_t entropy[64];
    size_t entropy_len = 0;
    char passphrase[256];
    size_t passphrase_len = 0;

    klog("kern-nexus seedkeeper: exporting id=%04x\n",
         headers[selected_header].id);
    int erc = seedkeeper_export_secret(&sk, headers[selected_header].id, secret,
                                       &secret_len);
    if (erc != 0 && sk.last_sw == 0) {
      /* The ISO-DEP link can idle out while the user reads the menu.  Bring
       * the card back and re-verify the PIN already in hand; do not ask for
       * it a second time. */
      klog("kern-nexus seedkeeper: export link lost, re-activating\n");
      if (kern_nfc_bring_up(&nfc) == 0 && seedkeeper_refresh(&sk) == 0 &&
          seedkeeper_verify_pin(&sk, pin) == 0)
        erc = seedkeeper_export_secret(&sk, headers[selected_header].id,
                                       secret, &secret_len);
    }
    if (erc != 0) {
      klog("kern-nexus seedkeeper: export failed sw=%04x\n", sk.last_sw);
      if (sk.last_sw && sk.last_sw != SEEDKEEPER_SW_OK) {
        char text[64];
        seedkeeper_describe_status(sk.last_sw, text, sizeof(text));
        set_error(text);
      } else {
        set_error("Card communication failed");
      }
      memset(secret, 0, sizeof(secret));
      return;
    }
    klog("kern-nexus seedkeeper: exported %zu bytes\n", secret_len);
    if (seedkeeper_unpack_bip39(secret, secret_len, entropy, sizeof(entropy),
                                &entropy_len, passphrase, sizeof(passphrase),
                                &passphrase_len) != 0) {
      set_error("Secret is not a BIP39 Masterseed");
      memset(secret, 0, sizeof(secret));
      return;
    }
    memset(secret, 0, sizeof(secret));

    work_has_passphrase = passphrase_len > 0;
    if (work_has_passphrase)
      memcpy(work_passphrase, passphrase, passphrase_len + 1);
    else
      work_passphrase[0] = '\0';
    memset(passphrase, 0, sizeof(passphrase));

    SECURE_FREE_STRING(work_mnemonic);
    if (kern_bip39_mnemonic_from_bytes(NULL, entropy, entropy_len,
                                       &work_mnemonic) != WALLY_OK ||
        !work_mnemonic) {
      set_error("Could not encode the mnemonic");
      memset(entropy, 0, sizeof(entropy));
      return;
    }
    memset(entropy, 0, sizeof(entropy));
    work_rc = 0;
    return;
  }

  if (nfc.fd < 0 && kern_nfc_open(&nfc) != 0) {
    set_error("NFC device unavailable");
    return;
  }
  if (kern_nfc_bring_up(&nfc) != 0) {
    klog("kern-nexus seedkeeper: no tag\n");
    set_error("No card found");
    return;
  }
  klog("kern-nexus seedkeeper: tag active\n");
  seedkeeper_init(&sk, (kern_nfc_transport_t){nfc_transmit}, &nfc);
  if (seedkeeper_refresh(&sk) != 0) {
    klog("kern-nexus seedkeeper: select failed sw=%04x\n", sk.last_sw);
    set_error("Card communication failed");
    return;
  }
  kern_seedkeeper_card_status_t status;
  if (seedkeeper_card_status(&sk, &status) != 0) {
    klog("kern-nexus seedkeeper: status failed sw=%04x\n", sk.last_sw);
    set_error("Could not read card status");
    return;
  }
  klog("kern-nexus seedkeeper: applet v%u.%u, setup=%d, sc=%d\n",
       status.applet_major, status.applet_minor, status.setup_done,
       status.needs_secure_channel);

  if (seedkeeper_verify_pin(&sk, pin) != 0) {
    klog("kern-nexus seedkeeper: PIN failed sw=%04x\n", sk.last_sw);
    if (sk.last_sw && sk.last_sw != SEEDKEEPER_SW_OK) {
      char text[64];
      seedkeeper_describe_status(sk.last_sw, text, sizeof(text));
      set_error(text);
    } else {
      set_error("Card authentication failed");
    }
    return;
  }

  header_count = MAX_SECRETS;
  size_t found = MAX_SECRETS;
  if (seedkeeper_list_headers(&sk, headers, &found) != 0) {
    klog("kern-nexus seedkeeper: list failed sw=%04x found=%zu\n",
         sk.last_sw, found);
    if (sk.last_sw && sk.last_sw != SEEDKEEPER_SW_OK) {
      char text[64];
      seedkeeper_describe_status(sk.last_sw, text, sizeof(text));
      set_error(text);
    } else {
      set_error("Card communication failed");
    }
    header_count = 0;
    return;
  }
  klog("kern-nexus seedkeeper: %zu headers\n", found);
  for (size_t i = 0; i < found; i++)
    klog("kern-nexus seedkeeper: header %04x type=%02x subtype=%02x label=%s\n",
         headers[i].id, headers[i].type, headers[i].subtype,
         headers[i].label_valid ? headers[i].label : "?");
  header_count = found;
  work_rc = 0;
}

static void show_pin(void);
static void start_export(void);
static void menu_show(void);
static void key_success_cb(void);
static void key_return_cb(void);

static void finish_return(void) {
  void (*callback)(void) = return_callback;
  load_seedkeeper_page_destroy();
  if (callback)
    callback();
}

static void poll_cb(lv_timer_t *timer) {
  (void)timer;
  if (!work_done)
    return;
  worker_task_wait();
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  hide_progress();
  working = false;

  if (cancel_requested) {
    finish_return();
    return;
  }

  if (work_rc != 0) {
    const char *text = work_error[0] ? work_error : "Card error";
    if (work_kind == WORK_LOGIN)
      dialog_show_error_timeout(text, show_pin, 5000);
    else if (work_kind == WORK_EXPORT)
      dialog_show_error_timeout(text, menu_show, 5000);
    else
      finish_return();
    return;
  }

  switch (work_kind) {
  case WORK_LOGIN:
    if (header_count == 0)
      dialog_show_error_timeout("No secrets on the card", show_pin, 5000);
    else if (header_count == 1) {
      selected_header = 0;
      start_export();
    } else {
      menu_show();
    }
    break;
  case WORK_EXPORT:
    load_seedkeeper_page_hide();
    key_confirmation_page_create_passphrase(
        lv_screen_active(), key_return_cb, key_success_cb, work_mnemonic,
        strlen(work_mnemonic), work_passphrase, work_has_passphrase);
    break;
  default:
    break;
  }
}

static void start_worker(work_kind_t kind, const char *title,
                         const char *text) {
  work_kind = kind;
  working = true;
  work_done = false;
  work_rc = 0;
  work_error[0] = '\0';
  show_progress(title, text);
  if (!worker_task_start("seedkeeper", WORKER_STACK, card_work, &work_done)) {
    hide_progress();
    dialog_show_error_timeout("Task creation failed", return_callback, 0);
    return;
  }
  poll_timer = lv_timer_create(poll_cb, 100, NULL);
}

static void back_cb(lv_event_t *e) {
  (void)e;
  if (working) {
    cancel_requested = true;
    kern_nfc_cancel();
    show_progress("SeedKeeper", "Cancelling...");
    return;
  }
  finish_return();
}

static void pin_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(pin_input.textarea);
  size_t len = text ? strlen(text) : 0;
  if (len < SEEDKEEPER_PIN_MIN || len > SEEDKEEPER_PIN_MAX) {
    dialog_show_error_timeout("PIN must be 4 to 16 characters", NULL, 0);
    return;
  }
  memcpy(pin, text, len + 1);
  ui_secure_clear_textarea(pin_input.textarea);
  ui_text_input_hide(&pin_input);
  start_worker(WORK_LOGIN, "SeedKeeper", "Tap the card... (back arrow cancels)");
}

static void show_pin(void) {
  hide_progress();
  if (sk_menu) {
    ui_menu_destroy(sk_menu);
    sk_menu = NULL;
  }
  if (sk_menu_screen) {
    lv_obj_del(sk_menu_screen);
    sk_menu_screen = NULL;
  }
  if (!pin_input.textarea)
    ui_text_input_create(&pin_input, sk_screen, "PIN", true, pin_ready_cb);
  ui_text_input_show(&pin_input);
}

static void choose_header(size_t index) {
  selected_header = index;
  if (sk_menu)
    ui_menu_hide(sk_menu);
  start_export();
}

#define SELECT_CB(n)                                                           \
  static void select_##n(void) { choose_header(n); }
SELECT_CB(0)
SELECT_CB(1)
SELECT_CB(2)
SELECT_CB(3)
SELECT_CB(4)
SELECT_CB(5)
SELECT_CB(6)
SELECT_CB(7)
SELECT_CB(8)
SELECT_CB(9)
SELECT_CB(10)
SELECT_CB(11)
SELECT_CB(12)
SELECT_CB(13)
SELECT_CB(14)
SELECT_CB(15)

static ui_menu_callback_t select_cb(size_t index) {
  static ui_menu_callback_t callbacks[16] = {
      select_0,  select_1,  select_2,  select_3,  select_4,  select_5,
      select_6,  select_7,  select_8,  select_9,  select_10, select_11,
      select_12, select_13, select_14, select_15};
  return index < 16 ? callbacks[index] : NULL;
}

static void menu_show(void) {
  if (!sk_menu_screen) {
    sk_menu_screen = theme_create_page_container(lv_screen_active());
    if (!sk_menu_screen)
      return;
    sk_menu = ui_menu_create(sk_menu_screen, "Select Seed", show_pin);
    if (!sk_menu) {
      lv_obj_del(sk_menu_screen);
      sk_menu_screen = NULL;
      return;
    }
    for (size_t i = 0; i < header_count && i < MAX_SECRETS; i++) {
      char label[SEEDKEEPER_MAX_LABEL + 16];
      if (headers[i].label_valid && headers[i].label[0])
        snprintf(label, sizeof(label), "%s", headers[i].label);
      else
        snprintf(label, sizeof(label), "Secret %04x", headers[i].id);
      ui_menu_add_entry(sk_menu, label, select_cb(i));
    }
  }
  ui_menu_show(sk_menu);
}

static void start_export(void) {
  start_worker(WORK_EXPORT, "SeedKeeper", "Reading secret...");
}

static void key_success_cb(void) {
  void (*callback)(void) = success_callback;
  load_seedkeeper_page_destroy();
  if (callback)
    callback();
}

static void key_return_cb(void) {
  load_seedkeeper_page_show();
  show_pin();
}

void load_seedkeeper_page_create(lv_obj_t *parent, void (*return_cb)(void),
                                 void (*success_cb)(void)) {
  session_cleanup_register(load_seedkeeper_page_destroy);
  (void)parent;
  return_callback = return_cb;
  success_callback = success_cb;
  header_count = 0;
  selected_header = 0;
  memset(headers, 0, sizeof(headers));
  memset(&sk, 0, sizeof(sk));
  memset(pin, 0, sizeof(pin));
  nfc.fd = -1;
  work_kind = WORK_NONE;
  working = false;
  cancel_requested = false;
  work_done = false;
  work_mnemonic = NULL;
  work_passphrase[0] = '\0';
  work_has_passphrase = false;

  sk_screen = theme_create_page_container(lv_screen_active());
  if (!sk_screen)
    return;
  theme_create_page_title(sk_screen, "SeedKeeper");
  ui_create_back_button(sk_screen, back_cb);
  /* Ask for the PIN before touching the card: no SELECT, status or PIN-less
   * command is sent until the user has entered it. */
  show_pin();
}

void load_seedkeeper_page_show(void) {
  if (sk_screen)
    lv_obj_clear_flag(sk_screen, LV_OBJ_FLAG_HIDDEN);
}

void load_seedkeeper_page_hide(void) {
  if (sk_screen)
    lv_obj_add_flag(sk_screen, LV_OBJ_FLAG_HIDDEN);
  if (pin_input.keyboard)
    lv_obj_add_flag(pin_input.keyboard, LV_OBJ_FLAG_HIDDEN);
}

void load_seedkeeper_page_destroy(void) {
  session_cleanup_unregister(load_seedkeeper_page_destroy);
  kern_nfc_cancel();
  worker_task_wait();
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  hide_progress();
  if (sk_menu) {
    ui_menu_destroy(sk_menu);
    sk_menu = NULL;
  }
  if (sk_menu_screen) {
    lv_obj_del(sk_menu_screen);
    sk_menu_screen = NULL;
  }
  if (pin_input.textarea)
    ui_text_input_destroy(&pin_input);
  if (sk_screen) {
    lv_obj_del(sk_screen);
    sk_screen = NULL;
  }
  kern_nfc_close(&nfc);
  memset(&sk, 0, sizeof(sk));
  memset(pin, 0, sizeof(pin));
  memset(work_passphrase, 0, sizeof(work_passphrase));
  SECURE_FREE_STRING(work_mnemonic);
  work_has_passphrase = false;
  return_callback = NULL;
  success_callback = NULL;
}
