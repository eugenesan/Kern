/*
 * The shared SeedKeeper card page.
 *
 * Every SeedKeeper flow (load, new seed, backup, list, delete, card info)
 * needs the same three things: the PIN before the card is touched, a
 * session that survives the user reading a menu, and a way to run a
 * blocking card command off the LVGL thread.  This module owns all three.
 *
 * The card work runs on the shared worker task and an LVGL timer polls it,
 * so the UI thread never touches the NFC fd and never blocks on an APDU.
 */

#ifndef SEEDKEEPER_PAGE_H
#define SEEDKEEPER_PAGE_H

#include <lvgl.h>
#include <stdbool.h>
#include <stddef.h>

#include "seedkeeper.h"

/* --- the card session -------------------------------------------------- */

/* The NFC handle, the applet session and the PIN the user typed.  One
 * session is live at a time: the page owns it. */
typedef struct {
  kern_nfc_t nfc;
  kern_seedkeeper_t sk;
  char pin[SEEDKEEPER_PIN_MAX + 1];
  int logged_in;
} seedkeeper_card_t;

/* A card command.  Runs on the worker task, so it may block.  Returns 0
 * on success; on failure it fills `err` with a short, user-readable
 * reason. */
typedef int (*seedkeeper_op_fn)(seedkeeper_card_t *card, void *ctx, char *err,
                                size_t err_cap);

/* Brings the card up, selects the applet, reads its status and verifies
 * the PIN.  Blocking: run it on the worker task. */
int seedkeeper_card_open(seedkeeper_card_t *card, const char *pin, char *err,
                          size_t err_cap);

/* Selects the applet again and re-verifies the PIN already in hand.  Used
 * when the ISO-DEP link idled out while the user was reading a menu.
 * Blocking: run it on the worker task. */
int seedkeeper_card_relogin(seedkeeper_card_t *card, char *err, size_t err_cap);

/* Runs `op`, and when it fails on a lost link, brings the card back and
 * runs it once more.  Only pass retry_on_link_loss for commands that can
 * safely be repeated; an import or a delete must not be.  Blocking: run it
 * on the worker task. */
int seedkeeper_card_run(seedkeeper_card_t *card, seedkeeper_op_fn op, void *ctx,
                        bool retry_on_link_loss, char *err, size_t err_cap);

/* --- the page ----------------------------------------------------------- */

/* Creates the page: a title, a back arrow and the PIN field.  The PIN is
 * asked for before any card command is sent.  `opened_cb` runs on the UI
 * thread once the card is open and the PIN is verified. */
void seedkeeper_page_create(lv_obj_t *parent, const char *title,
                             void (*return_cb)(void), void (*opened_cb)(void));

/* The same, but the PIN is not checked against the card yet: nothing is
 * sent until the flow calls seedkeeper_card_relogin().  A flow that has
 * questions to ask -- a label, a passphrase -- collects them first, so
 * the card is asked for once, when the write is ready, instead of being
 * held to the phone while the user types and then found gone. */
void seedkeeper_page_create_deferred(lv_obj_t *parent, const char *title,
                                     void (*return_cb)(void),
                                     void (*opened_cb)(void));

void seedkeeper_page_show(void);
void seedkeeper_page_hide(void);
void seedkeeper_page_destroy(void);

/* The card session of the live page. */
seedkeeper_card_t *seedkeeper_page_card(void);

/* The page container, so a flow can add its own view to it. */
lv_obj_t *seedkeeper_page_container(void);

/* Runs a card command: shows the progress dialog, runs `step` on the
 * worker task and calls `done` on the UI thread when it succeeded.  When it
 * fails, the page shows an error panel with Back and Retry; Retry runs the
 * step again.  Pass retry_on_link_loss only for commands that can safely be
 * repeated after the ISO-DEP link dropped. */
void seedkeeper_page_run(const char *progress_text, seedkeeper_op_fn step,
                         bool retry_on_link_loss, void (*done)(void *ctx),
                         void *ctx);

/* Shows an error panel on the page.  `retry` may be NULL for an error
 * without a way forward. */
void seedkeeper_page_error(const char *text, void (*retry)(void));

/* Hides the error panel, if any. */
void seedkeeper_page_hide_error(void);

/* A read-only block of text on the page, for card info and results. */
lv_obj_t *seedkeeper_page_text(const char *text);

/* Turns a card status word into a user-readable reason, using the card's
 * own wording where it has one. */
void seedkeeper_page_describe_status(uint16_t sw, char *buf, size_t cap);

/* Writes a line to the kernel log. */
void seedkeeper_page_log(const char *fmt, ...);

#endif /* SEEDKEEPER_PAGE_H */
