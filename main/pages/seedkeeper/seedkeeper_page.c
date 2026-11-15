/*
 * The shared SeedKeeper card page.
 *
 * See seedkeeper_page.h for the shape of this module.
 */

#include "seedkeeper_page.h"

#include "../../ui/dialog.h"
#include "../../ui/input_helpers.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/secure_mem.h"
#include "../../utils/session_cleanup.h"
#include "../../utils/worker_task.h"
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define WORKER_STACK 12288
#define ERR_LEN 96

static lv_obj_t *sk_screen = NULL;
static ui_text_input_t pin_input = {0};
static lv_obj_t *progress_dialog = NULL;
static lv_obj_t *error_panel = NULL;
static void (*error_retry_cb)(void) = NULL;

static seedkeeper_card_t card;
/* The PIN the user typed, kept between the keyboard callback and the
 * worker step that opens the card. */
static char pin_text[SEEDKEEPER_PIN_MAX + 1];
static void (*return_callback)(void) = NULL;
static void (*opened_callback)(void) = NULL;

static lv_timer_t *poll_timer = NULL;
static volatile bool work_done = false;
static bool working = false;
static volatile bool cancel_requested = false;

/* The step that is running, kept so that Retry can run it again. */
static seedkeeper_op_fn last_step = NULL;
static bool last_retry_on_link_loss = false;
static void (*last_done)(void *ctx) = NULL;
static void *last_ctx = NULL;
static char last_progress[64];

static void retry_last_step(void);
static int step_open(seedkeeper_card_t *c, void *ctx, char *err,
                     size_t err_cap);
static void done_open(void *ctx);
static void show_pin_input(void);
static void pin_ready_cb(lv_event_t *e);

void seedkeeper_page_log(const char *fmt, ...) {
  int fd = open("/dev/kmsg", O_WRONLY);
  if (fd >= 0) {
    va_list ap;
    va_start(ap, fmt);
    vdprintf(fd, fmt, ap);
    va_end(ap);
    close(fd);
  }
}

void seedkeeper_page_describe_status(uint16_t sw, char *buf, size_t cap) {
  if (sw == 0) {
    snprintf(buf, cap, "Card communication failed");
    return;
  }
  seedkeeper_describe_status(sw, buf, cap);
}

/* --- the card session -------------------------------------------------- */

static int nfc_transmit(void *ctx, const uint8_t *apdu, size_t apdu_len,
                        uint8_t *resp, size_t *resp_len, uint8_t *sw1,
                        uint8_t *sw2) {
  return kern_nfc_transceive((kern_nfc_t *)ctx, apdu, apdu_len, resp, resp_len,
                             sw1, sw2);
}

/* Selects the applet, reads its status and verifies the PIN.  The NFC
 * bring-up is done by the caller. */
static int card_login(seedkeeper_card_t *c, char *err, size_t err_cap) {
  kern_seedkeeper_card_status_t status;

  if (seedkeeper_refresh(&c->sk) != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  if (seedkeeper_card_status(&c->sk, &status) != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  seedkeeper_page_log("kern-nexus seedkeeper: applet v%u.%u, setup=%d, sc=%d\n",
       status.applet_major, status.applet_minor, status.setup_done,
       status.needs_secure_channel);
  if (!status.setup_done) {
    snprintf(err, err_cap, "Card is not set up");
    return -1;
  }
  if (seedkeeper_verify_pin(&c->sk, c->pin) != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  c->logged_in = 1;
  return 0;
}

int seedkeeper_card_open(seedkeeper_card_t *c, const char *pin, char *err,
                         size_t err_cap) {
  char copy[SEEDKEEPER_PIN_MAX + 1];
  size_t len;

  if (!c || !pin) {
    snprintf(err, err_cap, "Bad argument");
    return -1;
  }
  /* The page passes c->pin back in, so copy before clearing the field. */
  len = strlen(pin);
  if (len < SEEDKEEPER_PIN_MIN || len > SEEDKEEPER_PIN_MAX) {
    snprintf(err, err_cap, "PIN must be %d to %d characters",
             SEEDKEEPER_PIN_MIN, SEEDKEEPER_PIN_MAX);
    return -1;
  }
  memcpy(copy, pin, len + 1);
  memset(c->pin, 0, sizeof(c->pin));
  memcpy(c->pin, copy, len + 1);
  secure_memzero(copy, sizeof(copy));
  c->logged_in = 0;

  if (c->nfc.fd < 0 && kern_nfc_open(&c->nfc) != 0) {
    snprintf(err, err_cap, "NFC device unavailable");
    return -1;
  }
  if (kern_nfc_bring_up(&c->nfc) != 0) {
    seedkeeper_page_log("kern-nexus seedkeeper: no tag\n");
    snprintf(err, err_cap, "No card found");
    return -1;
  }
  seedkeeper_page_log("kern-nexus seedkeeper: tag active\n");
  seedkeeper_init(&c->sk, (kern_nfc_transport_t){nfc_transmit}, &c->nfc);
  return card_login(c, err, err_cap);
}

int seedkeeper_card_relogin(seedkeeper_card_t *c, char *err, size_t err_cap) {
  if (!c) {
    snprintf(err, err_cap, "Bad argument");
    return -1;
  }
  seedkeeper_page_log("kern-nexus seedkeeper: link lost, re-activating\n");
  if (c->nfc.fd < 0 && kern_nfc_open(&c->nfc) != 0) {
    snprintf(err, err_cap, "NFC device unavailable");
    return -1;
  }
  if (kern_nfc_bring_up(&c->nfc) != 0) {
    snprintf(err, err_cap, "No card found");
    return -1;
  }
  seedkeeper_init(&c->sk, (kern_nfc_transport_t){nfc_transmit}, &c->nfc);
  return card_login(c, err, err_cap);
}

int seedkeeper_card_run(seedkeeper_card_t *c, seedkeeper_op_fn op, void *ctx,
                        bool retry_on_link_loss, char *err, size_t err_cap) {
  int rc;

  if (!c || !op) {
    snprintf(err, err_cap, "Bad argument");
    return -1;
  }
  err[0] = '\0';
  rc = op(c, ctx, err, err_cap);
  if (rc == 0)
    return 0;
  /* A card status word is final; only a lost link is worth retrying. */
  if (!retry_on_link_loss || c->sk.last_sw != 0)
    return rc;
  if (seedkeeper_card_relogin(c, err, err_cap) != 0)
    return rc;
  return op(c, ctx, err, err_cap);
}

/* --- the page ---------------------------------------------------------- */

static void hide_progress(void) {
  if (progress_dialog) {
    lv_obj_del(progress_dialog);
    progress_dialog = NULL;
  }
}

static void show_progress(const char *title, const char *text) {
  hide_progress();
  progress_dialog = dialog_show_progress(title, text, DIALOG_STYLE_OVERLAY);
}

void seedkeeper_page_hide_error(void) {
  if (error_panel) {
    lv_obj_del(error_panel);
    error_panel = NULL;
  }
  error_retry_cb = NULL;
}

static void finish_return(void);

static void error_back_cb(lv_event_t *e) {
  (void)e;
  finish_return();
}

static void error_retry_event_cb(lv_event_t *e) {
  (void)e;
  void (*retry)(void) = error_retry_cb;
  seedkeeper_page_hide_error();
  if (retry)
    retry();
}

/* Errors stay on the page.  A modal dialog can outlive the page and then
 * call back into deleted LVGL objects, which freezes the UI. */
void seedkeeper_page_error(const char *text, void (*retry)(void)) {
  seedkeeper_page_hide_error();
  if (!sk_screen)
    return;
  error_retry_cb = retry;

  error_panel = lv_obj_create(sk_screen);
  lv_obj_remove_style_all(error_panel);
  lv_obj_set_size(error_panel, LV_PCT(100), LV_PCT(100));
  lv_obj_set_style_bg_color(error_panel, bg_color(), 0);
  lv_obj_set_style_bg_opa(error_panel, LV_OPA_COVER, 0);
  lv_obj_clear_flag(error_panel, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *label = lv_label_create(error_panel);
  lv_label_set_text(label, text ? text : "Card error");
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(label, LV_PCT(80));
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_CENTER, 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  lv_obj_set_style_text_color(label, error_color(), 0);
  lv_obj_align(label, LV_ALIGN_CENTER, 0, -80);

  lv_obj_t *row = lv_obj_create(error_panel);
  lv_obj_remove_style_all(row);
  lv_obj_set_size(row, LV_PCT(80), 90);
  lv_obj_align(row, LV_ALIGN_CENTER, 0, 100);
  lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
  lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_EVENLY,
                        LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
  lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

  lv_obj_t *back = lv_button_create(row);
  lv_obj_set_size(back, 220, 80);
  lv_obj_add_event_cb(back, error_back_cb, LV_EVENT_CLICKED, NULL);
  lv_obj_t *back_label = lv_label_create(back);
  lv_label_set_text(back_label, "Back");
  lv_obj_center(back_label);

  if (retry) {
    lv_obj_t *again = lv_button_create(row);
    lv_obj_set_size(again, 220, 80);
    lv_obj_add_event_cb(again, error_retry_event_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *again_label = lv_label_create(again);
    lv_label_set_text(again_label, "Retry");
    lv_obj_center(again_label);
  }
}

lv_obj_t *seedkeeper_page_text(const char *text) {
  lv_obj_t *box;
  lv_obj_t *label;

  if (!sk_screen)
    return NULL;
  /* A card can hold a long list, so the text goes into a scrollable box
   * instead of running off the screen. */
  box = lv_obj_create(sk_screen);
  lv_obj_set_size(box, LV_PCT(94), LV_PCT(80));
  lv_obj_align(box, LV_ALIGN_CENTER, 0, 20);
  lv_obj_set_style_bg_opa(box, LV_OPA_TRANSP, 0);
  lv_obj_set_style_border_width(box, 0, 0);
  lv_obj_set_style_pad_all(box, 4, 0);
  lv_obj_set_scrollbar_mode(box, LV_SCROLLBAR_MODE_AUTO);
  lv_obj_set_scroll_dir(box, LV_DIR_VER);
  lv_obj_set_flex_flow(box, LV_FLEX_FLOW_COLUMN);
  lv_obj_set_flex_align(box, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                        LV_FLEX_ALIGN_START);

  label = lv_label_create(box);
  lv_label_set_text(label, text ? text : "");
  lv_label_set_long_mode(label, LV_LABEL_LONG_WRAP);
  lv_obj_set_width(label, LV_PCT(96));
  lv_obj_set_style_text_align(label, LV_TEXT_ALIGN_LEFT, 0);
  lv_obj_set_style_text_font(label, theme_font_medium(), 0);
  return label;
}

/* --- the worker -------------------------------------------------------- */

static char work_error[ERR_LEN];

/* Runs on the worker task; never touches LVGL. */
static void card_work(void) {
  char err[ERR_LEN] = {0};

  work_error[0] = '\0';
  if (seedkeeper_card_run(&card, last_step, last_ctx, last_retry_on_link_loss,
                          err, sizeof(err)) != 0) {
    snprintf(work_error, sizeof(work_error), "%s",
             err[0] ? err : "Card error");
  }
  work_done = true;
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
  if (work_error[0]) {
    char text[ERR_LEN];
    snprintf(text, sizeof(text), "%s", work_error);
    seedkeeper_page_error(text, last_step ? retry_last_step : NULL);
    return;
  }
  if (last_done)
    last_done(last_ctx);
}

static void retry_last_step(void) {
  seedkeeper_page_run(last_progress, last_step, last_retry_on_link_loss,
                       last_done, last_ctx);
}

void seedkeeper_page_run(const char *progress_text, seedkeeper_op_fn step,
                         bool retry_on_link_loss, void (*done)(void *ctx),
                         void *ctx) {
  char text[64];

  last_step = step;
  last_retry_on_link_loss = retry_on_link_loss;
  last_done = done;
  last_ctx = ctx;
  /* The retry path passes last_progress back in, so copy through a
   * scratch buffer instead of formatting onto itself. */
  snprintf(text, sizeof(text), "%s",
           progress_text ? progress_text : "SeedKeeper");
  memcpy(last_progress, text, sizeof(text));

  work_done = false;
  working = true;
  cancel_requested = false;
  show_progress("SeedKeeper", last_progress);
  if (!worker_task_start("seedkeeper", WORKER_STACK, card_work, &work_done)) {
    hide_progress();
    working = false;
    seedkeeper_page_error("Task creation failed", NULL);
    return;
  }
  poll_timer = lv_timer_create(poll_cb, 100, NULL);
}

/* --- the PIN ------------------------------------------------------------ */

static void show_pin_input(void) {
  if (!pin_input.textarea)
    ui_text_input_create(&pin_input, sk_screen, "PIN", true, pin_ready_cb);
  if (pin_input.keyboard)
    lv_keyboard_set_mode(pin_input.keyboard, LV_KEYBOARD_MODE_NUMBER);
  ui_text_input_show(&pin_input);
}

static void pin_ready_cb(lv_event_t *e) {
  (void)e;
  const char *text = lv_textarea_get_text(pin_input.textarea);
  size_t len = text ? strlen(text) : 0;

  if (len < SEEDKEEPER_PIN_MIN || len > SEEDKEEPER_PIN_MAX) {
    seedkeeper_page_error("PIN must be 4 to 16 characters", show_pin_input);
    return;
  }
  memcpy(pin_text, text, len + 1);
  ui_secure_clear_textarea(pin_input.textarea);
  ui_text_input_hide(&pin_input);
  seedkeeper_page_run("Tap the card... (back arrow cancels)", step_open, false,
                       done_open, NULL);
}

/* Runs on the worker task. */
static int step_open(seedkeeper_card_t *c, void *ctx, char *err,
                     size_t err_cap) {
  (void)ctx;
  return seedkeeper_card_open(c, pin_text, err, err_cap);
}

/* Runs on the UI thread. */
static void done_open(void *ctx) {
  (void)ctx;
  if (opened_callback)
    opened_callback();
}

/* --- lifecycle ---------------------------------------------------------- */

static void finish_return(void) {
  void (*callback)(void) = return_callback;
  seedkeeper_page_destroy();
  if (callback)
    callback();
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

void seedkeeper_page_create(lv_obj_t *parent, const char *title,
                            void (*return_cb)(void), void (*opened_cb)(void)) {
  session_cleanup_register(seedkeeper_page_destroy);
  (void)parent;
  return_callback = return_cb;
  opened_callback = opened_cb;

  memset(&card, 0, sizeof(card));
  card.nfc.fd = -1;
  secure_memzero(pin_text, sizeof(pin_text));
  work_done = false;
  working = false;
  cancel_requested = false;
  last_step = NULL;
  last_done = NULL;
  last_ctx = NULL;
  work_error[0] = '\0';

  sk_screen = theme_create_page_container(lv_screen_active());
  if (!sk_screen)
    return;
  theme_create_page_title(sk_screen, title ? title : "SeedKeeper");
  ui_create_back_button(sk_screen, back_cb);

  /* Ask for the PIN before touching the card: no SELECT, status or
   * PIN-less command is sent until the user has entered it. */
  show_pin_input();
}

void seedkeeper_page_show(void) {
  if (sk_screen)
    lv_obj_clear_flag(sk_screen, LV_OBJ_FLAG_HIDDEN);
}

void seedkeeper_page_hide(void) {
  if (sk_screen)
    lv_obj_add_flag(sk_screen, LV_OBJ_FLAG_HIDDEN);
}

void seedkeeper_page_destroy(void) {
  session_cleanup_unregister(seedkeeper_page_destroy);
  kern_nfc_cancel();
  worker_task_wait();
  if (poll_timer) {
    lv_timer_del(poll_timer);
    poll_timer = NULL;
  }
  hide_progress();
  seedkeeper_page_hide_error();
  if (pin_input.textarea)
    ui_text_input_destroy(&pin_input);
  if (sk_screen) {
    lv_obj_del(sk_screen);
    sk_screen = NULL;
  }
  kern_nfc_close(&card.nfc);
  memset(&card, 0, sizeof(card));
  secure_memzero(pin_text, sizeof(pin_text));
  card.nfc.fd = -1;
  memset(card.pin, 0, sizeof(card.pin));
  memset(work_error, 0, sizeof(work_error));
  return_callback = NULL;
  opened_callback = NULL;
  last_step = NULL;
  last_done = NULL;
  last_ctx = NULL;
}

seedkeeper_card_t *seedkeeper_page_card(void) { return &card; }

lv_obj_t *seedkeeper_page_container(void) { return sk_screen; }
