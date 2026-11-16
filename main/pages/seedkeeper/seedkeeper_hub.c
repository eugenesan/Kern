/*
 * The SeedKeeper card menu.
 *
 * Every entry opens the card with the shared card page: the user enters the
 * PIN, the card is verified, and the operation runs on the worker task.
 * Results are presented as menus, like the rest of the settings pages, so a
 * list of secrets can be walked and a secret inspected.
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
#define MAX_ROWS 12
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

/* The menu that picks a secret, for both listing and deleting. */
static ui_menu_t *secret_menu = NULL;
static lv_obj_t *secret_menu_screen = NULL;

/* A menu of read-only rows: a secret's properties, card info, free space. */
static ui_menu_t *rows_menu = NULL;
static lv_obj_t *rows_screen = NULL;
static char rows_text[MAX_ROWS][80];

static op_kind_t current_op = OP_LIST;
static kern_seedkeeper_header_t headers[MAX_SECRETS];
static size_t header_count = 0;
static kern_seedkeeper_card_status_t card_status;
static kern_seedkeeper_memory_status_t card_memory;

/* The id the confirmation dialog is about; the dialog is asynchronous. */
static uint16_t pending_delete_id = 0;

static void op_opened(void);
static void hub_page_return_cb(void);
static void show_secret_menu(void);
static void show_rows(const char *title, void (*back)(void));
static void destroy_rows(void);
static void done_list(void *ctx);
static void done_delete(void *ctx);

/* --- helpers ------------------------------------------------------------ */

static const char *secret_type_name(uint8_t type) {
  switch (type) {
  case SEEDKEEPER_TYPE_MASTERSEED:
    return "Masterseed";
  case SEEDKEEPER_TYPE_BIP39_MNEMONIC:
    return "BIP39 mnemonic";
  case SEEDKEEPER_TYPE_PASSWORD:
    return "Password";
  case SEEDKEEPER_TYPE_DATA:
    return "Data";
  case SEEDKEEPER_TYPE_DESCRIPTOR:
    return "Descriptor";
  default:
    return "Unknown";
  }
}

static const char *secret_subtype_name(uint8_t type, uint8_t subtype) {
  if (type == SEEDKEEPER_TYPE_MASTERSEED && subtype == SEEDKEEPER_SUBTYPE_BIP39)
    return "BIP39";
  return "-";
}

static const char *export_rights_name(uint8_t rights) {
  switch (rights & 0x03) {
  case 0x01:
    return "Plaintext allowed";
  case 0x02:
    return "Secure only";
  default:
    return "Forbidden";
  }
}

static void noop_cb(void) {}

static void destroy_secret_menu(void) {
  if (secret_menu) {
    ui_menu_destroy(secret_menu);
    secret_menu = NULL;
  }
  if (secret_menu_screen) {
    lv_obj_del(secret_menu_screen);
    secret_menu_screen = NULL;
  }
}

static void destroy_rows(void) {
  if (rows_menu) {
    ui_menu_destroy(rows_menu);
    rows_menu = NULL;
  }
  if (rows_screen) {
    lv_obj_del(rows_screen);
    rows_screen = NULL;
  }
}

/* A page of read-only rows, in the same shape as any other menu. */
static void show_rows(const char *title, void (*back)(void)) {
  destroy_rows();
  rows_screen = theme_create_page_container(lv_screen_active());
  if (!rows_screen)
    return;
  rows_menu = ui_menu_create(rows_screen, title, back);
  if (!rows_menu)
    return;
  for (size_t i = 0; i < MAX_ROWS; i++) {
    if (!rows_text[i][0])
      break;
    ui_menu_add_entry(rows_menu, rows_text[i], noop_cb);
  }
  ui_menu_show(rows_menu);
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
  /* rc == 1 means the secret is already gone, which is the goal. */
  return 0;
}

/* --- the secret menu ---------------------------------------------------- */

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

/* Back from the secret menu returns to the hub, not to an empty card page. */
static void secret_menu_back_cb(void) {
  destroy_secret_menu();
  hub_page_return_cb();
}

static void show_secret_menu(void) {
  if (!secret_menu_screen) {
    secret_menu_screen = theme_create_page_container(lv_screen_active());
    if (!secret_menu_screen)
      return;
    secret_menu = ui_menu_create(
        secret_menu_screen,
        current_op == OP_DELETE ? "Delete Secret" : "Secrets",
        secret_menu_back_cb);
    if (!secret_menu) {
      lv_obj_del(secret_menu_screen);
      secret_menu_screen = NULL;
      return;
    }
    if (header_count == 0) {
      ui_menu_add_entry(secret_menu, "No secrets on the card", noop_cb);
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

/* --- viewing a secret --------------------------------------------------- */

static void rows_back_to_list(void) {
  destroy_rows();
  show_secret_menu();
}

static void show_secret_properties(size_t index) {
  const kern_seedkeeper_header_t *h = &headers[index];
  char fingerprint[2 * SEEDKEEPER_FINGERPRINT_SIZE + 1];
  size_t n = 0;

  for (size_t i = 0; i < SEEDKEEPER_FINGERPRINT_SIZE; i++)
    n += (size_t)snprintf(fingerprint + n, sizeof(fingerprint) - n, "%02x",
                          h->fingerprint[i]);

  memset(rows_text, 0, sizeof(rows_text));
  snprintf(rows_text[0], sizeof(rows_text[0]), "id  %04x", h->id);
  snprintf(rows_text[1], sizeof(rows_text[1]), "type  %s",
           secret_type_name(h->type));
  snprintf(rows_text[2], sizeof(rows_text[2]), "subtype  %s",
           secret_subtype_name(h->type, h->subtype));
  snprintf(rows_text[3], sizeof(rows_text[3]), "label  %s",
           (h->label_valid && h->label[0]) ? h->label : "-");
  snprintf(rows_text[4], sizeof(rows_text[4]), "export  %s",
           export_rights_name(h->export_rights));
  snprintf(rows_text[5], sizeof(rows_text[5]), "plain exports  %u",
           h->export_nbplain);
  snprintf(rows_text[6], sizeof(rows_text[6]), "secure exports  %u",
           h->export_nbsecure);
  snprintf(rows_text[7], sizeof(rows_text[7]), "fingerprint  %s", fingerprint);

  if (secret_menu)
    ui_menu_hide(secret_menu);
  show_rows("Secret", rows_back_to_list);
}

/* --- deleting a secret -------------------------------------------------- */

static void confirm_delete_cb(bool confirmed, void *user_data) {
  (void)user_data;
  if (!confirmed)
    return;
  destroy_secret_menu();
  seedkeeper_page_run("Deleting...", step_delete, true, done_delete,
                       &pending_delete_id);
}

static void choose_secret(size_t index) {
  char text[128];

  if (index >= header_count)
    return;
  if (current_op == OP_DELETE) {
    pending_delete_id = headers[index].id;
    if (secret_menu)
      ui_menu_hide(secret_menu);
    snprintf(text, sizeof(text),
             "Delete the secret %04x?\n\nThis cannot be undone.",
             pending_delete_id);
    dialog_show_danger_confirm(text, confirm_delete_cb, &pending_delete_id,
                               DIALOG_STYLE_OVERLAY);
    return;
  }
  show_secret_properties(index);
}

/* After a delete the list is read again so the menu shows what is left. */
static void done_delete(void *ctx) {
  (void)ctx;
  destroy_secret_menu();
  seedkeeper_page_run("Reading the card...", step_list, true, done_list, NULL);
}

/* --- the results -------------------------------------------------------- */

static void done_list(void *ctx) {
  (void)ctx;
  show_secret_menu();
}

static void rows_back_to_hub(void) {
  destroy_rows();
  hub_page_return_cb();
}

static void done_info(void *ctx) {
  (void)ctx;
  memset(rows_text, 0, sizeof(rows_text));
  snprintf(rows_text[0], sizeof(rows_text[0]), "applet  %u.%u",
           card_status.applet_major, card_status.applet_minor);
  snprintf(rows_text[1], sizeof(rows_text[1]), "protocol  %u.%u",
           card_status.protocol_major, card_status.protocol_minor);
  snprintf(rows_text[2], sizeof(rows_text[2]), "secure channel  %s",
           card_status.needs_secure_channel ? "yes" : "no");
  snprintf(rows_text[3], sizeof(rows_text[3]), "setup done  %s",
           card_status.setup_done ? "yes" : "no");
  snprintf(rows_text[4], sizeof(rows_text[4]), "PIN tries left  %d",
           card_status.pin_tries_left);
  snprintf(rows_text[5], sizeof(rows_text[5]), "secrets  %u",
           card_memory.nb_secrets);
  show_rows("Card Info", rows_back_to_hub);
}

static void done_space(void *ctx) {
  unsigned used;
  unsigned percent;

  (void)ctx;
  used = card_memory.total_memory > card_memory.free_memory
             ? card_memory.total_memory - card_memory.free_memory
             : 0;
  percent = card_memory.total_memory
                ? (unsigned)((100u * card_memory.free_memory) /
                             card_memory.total_memory)
                : 0;
  memset(rows_text, 0, sizeof(rows_text));
  snprintf(rows_text[0], sizeof(rows_text[0]), "free  %u bytes",
           card_memory.free_memory);
  snprintf(rows_text[1], sizeof(rows_text[1]), "used  %u bytes", used);
  snprintf(rows_text[2], sizeof(rows_text[2]), "total  %u bytes",
           card_memory.total_memory);
  snprintf(rows_text[3], sizeof(rows_text[3]), "free  %u%%", percent);
  show_rows("Free Space", rows_back_to_hub);
}

/* --- the hub menu ------------------------------------------------------- */

static void start_op(op_kind_t op) {
  const char *title = "SeedKeeper";

  current_op = op;
  header_count = 0;
  memset(headers, 0, sizeof(headers));
  memset(rows_text, 0, sizeof(rows_text));
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
    done = done_list;
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

/* Back from the card page or from a result: the hub is still there. */
static void hub_page_return_cb(void) {
  destroy_rows();
  destroy_secret_menu();
  seedkeeper_page_destroy();
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
  memset(rows_text, 0, sizeof(rows_text));

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
  destroy_rows();
  destroy_secret_menu();
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
  memset(rows_text, 0, sizeof(rows_text));
  return_callback = NULL;
}
