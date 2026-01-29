#pragma once

#include "resource.h"


#ifdef  __cplusplus
extern "C" {
#endif
#include "picoquic.h"
    typedef enum {
        quicwind_work_item_connection,
        quicwind_work_item_load_file,
        quicwind_work_item_disconnect
    } quicwind_work_item_enum;

    typedef struct st_quicwind_work_item_t {
        struct st_quicwind_work_item_t * next;
        quicwind_work_item_enum item_type;
        int sel_cid;
        char name[256];
        char port[16];
        char doc[256];
        char alpn[64];
        char sni[256];
    } quicwind_work_item_t;

    void AppendText(TCHAR const *newText);

    picoquic_quic_t* quicwind_create_context(const char * alpn, int mtu_max, const char * root_crt, uint8_t client_cnx_id_length);
    DWORD WINAPI quicwind_background_thread(LPVOID lpParam);
    int quicwind_start_connection(picoquic_quic_t * qclient,
        char const * name, char const *port_number, char const * doc_name,
        char const * alpn, char const *sni);
    int quicwind_get_cnx_list(picoquic_quic_t * qclient, HWND hDlg, int list_box_id);
    int quicwind_load_file(picoquic_quic_t * qclient, int sel_cid, char const * doc_name);
    int quicwind_disconnect(picoquic_quic_t * qclient, int sel_cid);
    void quicwind_wake_up_network();
    void quicwind_orderly_exit(picoquic_quic_t * qclient, HANDLE qclient_thread, DWORD dw_qclient_thread_id);
    int quicwind_add_work_item(quicwind_work_item_enum item_type,
        int sel_cid, char const * name, char const *port_number, char const * doc_name, char const * alpn, char const *sni);

#ifdef  __cplusplus
}
#endif