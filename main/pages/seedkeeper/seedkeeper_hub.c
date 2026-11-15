/*
 * The SeedKeeper card menu.
 *
 * Every entry opens the card with the shared card page: the user enters
 * the PIN, the card is verified, and the operation runs on the worker
 * task.  The results are shown on the card page itself, so the hub stays
 * a plain menu.
 */

#include "seedkeeper_hub.h"

#include "../../ui/dialog.h"
#include "../../ui/menu.h"
#include "../../ui/theme_widgets.h"
#include "../../utils/session_cleanup.h"
#include "seedkeeper_page.h"
#include <stdio.h>
#include <string.h>

#define MAX_SECRETS 64
#define MAX_MENU_SECRETS 16

typedef enum {
  OP_LIST,
  OP_DELETE,
  OP_INFO,
  OP_SPACE,
} op_kind_t;

static ui_menu_t *hub_menu = NULL;
static lv_obj_t *hub_screen = NULL;
static void (*return_callback)(void) = NULL;

/* The menu that picks the secret to delete. */
static ui_menu_t *secret_menu = NULL;
static lv_obj_t *secret_menu_screen = NULL;

static op_kind_t current_op = OP_LIST;
static kern_seedkeeper_header_t headers[MAX_SECRETS];
static size_t header_count = 0;
static kern_seedkeeper_card_status_t card_status;
static kern_seedkeeper_memory_status_t card_memory;
/* The id the confirmation dialog is about; the dialog is asynchronous, so
 * it cannot point at a local. */
static uint16_t pending_delete_id = 0;

static void op_opened(void);
static void hub_page_return_cb(void);
static void show_secret_menu(void);

/* --- helpers ------------------------------------------------------------ */

static const char *secret_type_name(uint8_t type) {
  switch (type) {
  case SEEDKEEPER_TYPE_MASTERSEED:
    return "seed";
  case SEEDKEEPER_TYPE_BIP39_MNEMONIC:
    return "mnemonic";
  case SEEDKEEPER_TYPE_PASSWORD:
    return "password";
  case SEEDKEEPER_TYPE_DATA:
    return "data";
  case SEEDKEEPER_TYPE_DESCRIPTOR:
    return "descriptor";
  default:
    return "secret";
  }
}

/* --- the card steps ----------------------------------------------------- */

/* Runs on the worker task. */
static int step_list(seedkeeper_card_t *c, void *ctx, char *err,
                     size_t err_cap) {
  size_t found = MAX_SECRETS;
  int rc;

  (void)ctx;
  rc = seedkeeper_list_headers(&c->sk, headers, &found);
  if (rc != 0) {
    if (rc == SEEDKEEPER_ERR_SPACE) {
      snprintf(err, err_cap, "The card holds more than %d secrets",
               MAX_SECRETS);
      return -1;
    }
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  header_count = found;
  return 0;
}

/* Runs on the worker task. */
static int step_info(seedkeeper_card_t *c, void *ctx, char *err,
                     size_t err_cap) {
  (void)ctx;
  if (seedkeeper_card_status(&c->sk, &card_status) != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  if (seedkeeper_memory_status(&c->sk, &card_memory) != 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  return 0;
}

/* Runs on the worker task. */
static int step_delete(seedkeeper_card_t *c, void *ctx, char *err,
                       size_t err_cap) {
  uint16_t id = *(const uint16_t *)ctx;
  int rc;

  rc = seedkeeper_reset_secret(&c->sk, id);
  if (rc < 0) {
    seedkeeper_page_describe_status(c->sk.last_sw, err, err_cap);
    return -1;
  }
  if (rc == 1) {
    snprintf(err, err_cap, "That secret is already gone");
    return -1;
  }
  return 0;
}

/* --- the results -------------------------------------------------------- */

static void done_list(void *ctx) {
  char text[2048];
  size_t used = 0;

  (void)ctx;
  if (header_count == 0) {
    seedkeeper_page_text("The card holds no secrets.");
    return;
  }
  used = (size_t)snprintf(text, sizeof(text), "%zu secret%s on the card\n",
                          header_count, header_count == 1 ? "" : "s");
  for (size_t i = 0; i < header_count && used < sizeof(text); i++) {
    const char *label = headers[i].label_valid ? headers[i].label : "";
    used += (size_t)snprintf(text + used, sizeof(text) - used, "\n%04x  %-16s %s",
                             headers[i].id, label,
                             secret_type_name(headers[i].type));
  }
  seedkeeper_page_text(text);
}

static void done_info(void *ctx) {
  char text[320];

  (void)ctx;
  snprintf(text, sizeof(text),
           "Applet version      %u.%u\n"
           "Protocol version    %u.%u\n"
           "Secure channel      %s\n"
           "Setup done          %s\n"
           "PIN tries left      %d\n"
           "Secrets             %u\n"
           "Memory free         %u of %u bytes",
           card_status.applet_major, card_status.applet_minor,
           card_status.protocol_major, card_status.protocol_minor,
           card_status.needs_secure_channel ? "yes" : "no",
           card_status.setup_done ? "yes" : "no", card_status.pin_tries_left,
           card_memory.nb_secrets, card_memory.free_memory,
           card_memory.total_memory);
  seedkeeper_page_text(text);
}

static void done_space(void *ctx) {
  char text[160];
  unsigned used;

  (void)ctx;
  used = card_memory.total_memory > card_memory.free_memory
             ? card_memory.total_memory - card_memory.free_memory
             : 0;
  snprintf(text, sizeof(text),
           "Free space\n\n%u of %u bytes free\n%u bytes used\n\n%d%% free",
           card_memory.free_memory, card_memory.total_memory, used,
           card_memory.total_memory
               ? (unsigned)((100u * card_memory.free_memory) /
                            card_memory.total_memory)
               : 0);
  seedkeeper_page_text(text);
}

/* --- deleting a secret -------------------------------------------------- */

static void delete_finished(void *ctx) {
  (void)ctx;
  seedkeeper_page_hide_error();
  seedkeeper_page_text("The secret was deleted.");
}

static void delete_confirm_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  if (secret_menu_screen) {
    lv_obj_del(secret_menu_screen);
    secret_menu_screen = NULL;
  }
  seedkeeper_page_run("Deleting...", step_delete, false, delete_finished,
                       &pending_delete_id);
}

/* The list is only the first half of a delete: the user picks the secret
 * to remove from the menu. */
static void done_delete_list(void *ctx) {
  (void)ctx;
  show_secret_menu();
}

static void choose_secret(size_t index);

#define SELECT_CB(n)                                                           \
  static void select_##n(void) { choose_secret(n); }
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

static void secret_menu_back_cb(void) {
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  if (secret_menu_screen) {
    lv_obj_del(secret_menu_screen);
    secret_menu_screen = NULL;
  }
  seedkeeper_page_show();
}

static void choose_secret(size_t index) {
  char text[128];

  if (index >= header_count)
    return;
  pending_delete_id = headers[index].id;
  if (secret_menu)
    ui_menu_hide(secret_menu);
  snprintf(text, sizeof(text),
           "Delete the secret %04x?\n\nThis cannot be undone.",
           pending_delete_id);
  dialog_show_danger_confirm(text, delete_confirm_cb, &pending_delete_id,
                             DIALOG_STYLE_OVERLAY);
}

static void show_secret_menu(void) {
  if (!secret_menu_screen) {
    secret_menu_screen = theme_create_page_container(lv_screen_active());
    if (!secret_menu_screen)
      return;
    secret_menu = ui_menu_create(secret_menu_screen, "Delete Secret",
                                 secret_menu_back_cb);
    if (!secret_menu) {
      lv_obj_del(secret_menu_screen);
      secret_menu_screen = NULL;
      return;
    }
    for (size_t i = 0; i < header_count && i < MAX_MENU_SECRETS; i++) {
      char label[SEEDKEEPER_MAX_LABEL + 16];
      if (headers[i].label_valid && headers[i].label[0])
        snprintf(label, sizeof(label), "%s", headers[i].label);
      else
        snprintf(label, sizeof(label), "Secret %04x", headers[i].id);
      ui_menu_add_entry(secret_menu, label, select_cb(i));
    }
  }
  ui_menu_show(secret_menu);
}

/* --- the hub menu ------------------------------------------------------- */

static void start_op(op_kind_t op) {
  const char *title = "SeedKeeper";

  current_op = op;
  switch (op) {
  case OP_LIST:
    title = "Card Secrets";
    break;
  case OP_DELETE:
    title = "Delete Secret";
    break;
  case OP_INFO:
    title = "Card Info";
    break;
  case OP_SPACE:
    title = "Free Space";
    break;
  }

  if (hub_menu)
    ui_menu_hide(hub_menu);

  /* The card page asks for the PIN; once it is verified, op_opened runs
   * the operation. */
  seedkeeper_page_create(lv_screen_active(), title, hub_page_return_cb,
                          op_opened);
  seedkeeper_page_show();
}

static void op_opened(void) {
  seedkeeper_op_fn step = step_list;
  void (*done)(void *ctx) = done_list;

  switch (current_op) {
  case OP_LIST:
    step = step_list;
    done = done_list;
    break;
  case OP_DELETE:
    step = step_list;
    done = done_delete_list;
    break;
  case OP_INFO:
    step = step_info;
    done = done_info;
    break;
  case OP_SPACE:
    step = step_info;
    done = done_space;
    break;
  }
  seedkeeper_page_run("Reading the card...", step, true, done, NULL);
}

static void menu_list_cb(void) { start_op(OP_LIST); }
static void menu_delete_cb(void) { start_op(OP_DELETE); }
static void menu_info_cb(void) { start_op(OP_INFO); }
static void menu_space_cb(void) { start_op(OP_SPACE); }

/* Back from the card page: the hub is still there, with the other
 * operations on it. */
static void hub_page_return_cb(void) {
  seedkeeper_page_destroy();
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  if (secret_menu_screen) {
    lv_obj_del(secret_menu_screen);
    secret_menu_screen = NULL;
  }
  if (hub_menu)
    ui_menu_show(hub_menu);
}

static void back_cb(void) {
  void (*callback)(void) = return_callback;
  seedkeeper_hub_page_destroy();
  if (callback)
    callback();
}

/* --- lifecycle ---------------------------------------------------------- */

void seedkeeper_hub_page_create(lv_obj_t *parent, void (*return_cb)(void)) {
  session_cleanup_register(seedkeeper_hub_page_destroy);
  if (!parent)
    return;

  return_callback = return_cb;
  header_count = 0;
  memset(headers, 0, sizeof(headers));

  hub_screen = theme_create_page_container(parent);
  if (!hub_screen)
    return;

  hub_menu = ui_menu_create(hub_screen, "SeedKeeper", back_cb);
  if (!hub_menu)
    return;

  ui_menu_add_entry(hub_menu, "List Secrets", menu_list_cb);
  ui_menu_add_entry(hub_menu, "Delete Secret", menu_delete_cb);
  ui_menu_add_entry(hub_menu, "Card Info", menu_info_cb);
  ui_menu_add_entry(hub_menu, "Free Space", menu_space_cb);
  ui_menu_show(hub_menu);
}

void seedkeeper_hub_page_show(void) {
  if (hub_screen)
    lv_obj_clear_flag(hub_screen, LV_OBJ_FLAG_HIDDEN);
  if (hub_menu)
    ui_menu_show(hub_menu);
}

void seedkeeper_hub_page_hide(void) {
  if (hub_screen)
    lv_obj_add_flag(hub_screen, LV_OBJ_FLAG_HIDDEN);
  if (hub_menu)
    ui_menu_hide(hub_menu);
}

void seedkeeper_hub_page_destroy(void) {
  session_cleanup_unregister(seedkeeper_hub_page_destroy);
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  if (secret_menu_screen) {
    lv_obj_del(secret_menu_screen);
    secret_menu_screen = NULL;
  }
  seedkeeper_page_destroy();
  if (hub_menu) {
    ui_menu_destroy(hub_menu);
    hub_menu = NULL;
  }
  if (hub_screen) {
    lv_obj_del(hub_screen);
    hub_screen = NULL;
  }
  header_count = 0;
  memset(headers, 0, sizeof(headers));
  return_callback = NULL;
}
