// quicwind.cpp : 
// This is an exloration of using Picoquic in a windows desktop app.
// The app itself is a real time version of the picoquic demo.
// The application has two threads: the windows thread and the protocol thread.
// The protocol thread starts a quic context, and runs a loop to execute the
// protocol. It manages the sockets, etc.
//
// The windows thread manages the exchanges:
//   * start a connection to a specific destination (h3 or h09)
//   * ask for additional requests
//   * close the connection.
// The windows will report the last N messages on the UI, based on informations
// from the protocol callback.
// Since application and UI are in different threads, this should demonstrate 
// that the API is thread safe.
//
#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <WinSock2.h>
#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include "quicwind.h"


#define MAX_LOADSTRING 100

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
picoquic_quic_t * qclient = NULL;               // the quic client context.
HANDLE qclient_thread = NULL;
DWORD dw_qclient_thread_id = 0;
HWND hWndEdit = NULL;
#define IDC_EDITBOX 100

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    StartConnection(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    LoadFile(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    CloseConnection(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_QUICWIND, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_QUICWIND));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_QUICWIND));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_QUICWIND);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    RECT Rect;
    HWND hWnd = NULL;
    hInst = hInstance; // Store instance handle in our global variable

    hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd)
    {
        return FALSE;
    }

    if (!GetClientRect(hWnd, &Rect)) {
        Rect.left = 50;
        Rect.top = 100;
        Rect.right = Rect.left + 200;
        Rect.bottom = Rect.top + 100;
    }

    hWndEdit = CreateWindowEx(WS_EX_CLIENTEDGE,
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        Rect.left, Rect.top, Rect.right - Rect.left, Rect.bottom - Rect.top, hWnd,
        (HMENU)IDC_EDITBOX,
        GetModuleHandle(NULL),
        NULL);

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case ID_FILE_CONNECT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_CONNECT), hWnd, StartConnection);
                break;
            case ID_FILE_LOADFILE:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_LOAD_DOC), hWnd, LoadFile);
                break;
            case ID_FILE_CLOSE:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_CLOSE_CNX), hWnd, CloseConnection);
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                quicwind_orderly_exit(qclient, qclient_thread, dw_qclient_thread_id);
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;

    case WM_SIZE:
        // Make the edit control the size of the window's client area. 

        MoveWindow(hWndEdit,
            0, 0,                  // starting x- and y-coordinates 
            LOWORD(lParam),        // width of client area 
            HIWORD(lParam),        // height of client area 
            TRUE);                 // repaint window 
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

/* Adding text in the edit control */
extern "C" void AppendText(TCHAR const *newText)
{
    // get edit control from dialog
    HWND hwndOutput = hWndEdit; /* GetDlgItem(hwnd, IDC_EDITBOX); */

    // get the current selection
    DWORD StartPos, EndPos;
    SendMessage(hwndOutput, EM_GETSEL, reinterpret_cast<WPARAM>(&StartPos), reinterpret_cast<WPARAM>(&EndPos));

    // move the caret to the end of the text
    int outLength = GetWindowTextLength(hwndOutput);
    SendMessage(hwndOutput, EM_SETSEL, outLength, outLength);

    // insert the text at the new caret position
    SendMessage(hwndOutput, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(newText));

    // restore the previous selection
    // SendMessage(hwndOutput, EM_SETSEL, StartPos, EndPos);
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Message handler for connection start.
INT_PTR CALLBACK StartConnection(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG: {
        if (qclient == NULL) {
            qclient = quicwind_create_context(NULL, 1500, NULL, 8);

            if (qclient != NULL) {
                qclient_thread = CreateThread(NULL, 0, quicwind_background_thread, (void*)qclient, 0, &dw_qclient_thread_id);
            }
        }

        (void)SetDlgItemTextA(hDlg, IDC_SERVER_NAME, "test.privateoctopus.com");
        (void)SetDlgItemTextA(hDlg, IDC_PORT_NUMBER, "4433");
        return (INT_PTR)TRUE;
    }

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
          
            if (LOWORD(wParam) == IDOK) {
                char name[256];
                char port[16];
                char doc[256];
                char alpn[64];
                char sni[256];
                int name_len;
                int port_len;
                int doc_len;
                int alpn_len;
                int sni_len;

                name_len = GetDlgItemTextA(hDlg, IDC_SERVER_NAME, name, (int)sizeof(name));
                port_len = GetDlgItemTextA(hDlg, IDC_PORT_NUMBER, port, (int)sizeof(port));
                doc_len = GetDlgItemTextA(hDlg, IDC_DOC1, doc, (int)sizeof(doc));
                alpn_len = GetDlgItemTextA(hDlg, IDC_ALPN, alpn, (int)sizeof(alpn));
                sni_len = GetDlgItemTextA(hDlg, IDC_SNI, sni, (int)sizeof(sni));

                if (quicwind_add_work_item(quicwind_work_item_connection, 0,
                    (name_len > 0) ? name : NULL, (port_len > 0) ? port : NULL,
                    (doc_len > 0) ? doc : NULL, (alpn_len > 0) ? alpn : NULL,
                    (sni_len > 0) ? sni : NULL) != 0) {
                    MessageBox(hDlg, L"Could not create the connection",
                        L"Create Connection error", MB_OK);
                }
            }

            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Message handler for file load.
INT_PTR CALLBACK LoadFile(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG: {
        // Add items to list. 
        if (qclient == NULL || quicwind_get_cnx_list(qclient, hDlg, IDC_CNX_LIST2) <= 0) {
            MessageBox(hDlg, L"No connection available yet",
                L"Load File error", MB_OK);
            EndDialog(hDlg, LOWORD(IDCANCEL));
            return (INT_PTR)TRUE;
        }
        else {
            return (INT_PTR)TRUE;
        }
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            char doc[256];
            HWND hwndList = GetDlgItem(hDlg, IDC_CNX_LIST2);
            // Get selected index.
            int lbItem = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);
            // Get item data.
            int sel_cid = (int)SendMessage(hwndList, LB_GETITEMDATA, lbItem, 0);
            // Get the doc
            int doc_len = GetDlgItemTextA(hDlg, IDC_DOC2, doc, (int)sizeof(doc));

            if (quicwind_add_work_item(quicwind_work_item_load_file, sel_cid, NULL, NULL, doc, NULL, NULL) != 0) {
                MessageBox(hDlg, L"Something happened, could not request the document",
                    L"Load file error", MB_OK);
            }
            
            EndDialog(hDlg, LOWORD(wParam));

            return (INT_PTR)TRUE;

        } else if (LOWORD(wParam) == IDCANCEL){
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

// Message handler for connection close.
INT_PTR CALLBACK CloseConnection(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG: {
        if (qclient == NULL || quicwind_get_cnx_list(qclient, hDlg, IDC_CNX_LIST1) <= 0) {
            MessageBox(hDlg, L"No connection available yet",
                L"Close Connection error", MB_OK);
            EndDialog(hDlg, LOWORD(IDCANCEL));
            return (INT_PTR)TRUE;
        }
        else {
            return (INT_PTR)TRUE;
        }
    }

    case WM_COMMAND: 
        switch (LOWORD(wParam)) {
        case IDOK:
        {
            HWND hwndList = GetDlgItem(hDlg, IDC_CNX_LIST1);


            // Get selected index.
            int lbItem = (int)SendMessage(hwndList, LB_GETCURSEL, 0, 0);

            // Get item data.
            int sel_cid = (int)SendMessage(hwndList, LB_GETITEMDATA, lbItem, 0);

            if (quicwind_add_work_item(quicwind_work_item_disconnect, sel_cid, NULL, NULL, NULL, NULL, NULL) != 0) {
                MessageBox(hDlg, L"Something happened, could not close",
                    L"Close Connection error", MB_OK);
            }
            
            EndDialog(hDlg, LOWORD(wParam));

            return (INT_PTR)TRUE;
        }
        case IDCANCEL:
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
  
        break;
    }
    return (INT_PTR)FALSE;
}