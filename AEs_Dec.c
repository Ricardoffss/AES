#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#define NT_SUCCESS(Status) ((Status) >= 0)
#define KEYSIZE 32
#define IVSIZE 16

typedef struct _AES {

    PBYTE	pPlainText;         // �������ݵĻ���ַ
    DWORD	dwPlainSize;        // �������ݵĴ�С

    PBYTE	pCipherText;        // �������ݵĻ���ַ
    DWORD	dwCipherSize;       // �������ݵĴ�С�������������ݣ����ֵ���ܲ�ͬ�� dwPlainSize��

    PBYTE	pKey;               // 32 �ֽ���Կ
    PBYTE	pIv;                // 16 �ֽ� IV����ʼ��������

} AES, * PAES;
// ����ʵ��
BOOL InstallAesDecryption(PAES pAes) {

    BOOL                  bSTATE = TRUE;
    BCRYPT_ALG_HANDLE     hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE     hKeyHandle = NULL;

    ULONG                 cbResult = NULL;
    DWORD                 dwBlockSize = NULL;

    DWORD                 cbKeyObject = NULL;
    PBYTE                 pbKeyObject = NULL;

    PBYTE                 pbPlainText = NULL;
    DWORD                 cbPlainText = NULL;

    NTSTATUS STATUS = 0;
    // ʹ�� AES �㷨�����ʼ����hAlgorithm��
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider ʧ�ܣ�����Ϊ��0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ��ȡ��������� pbKeyObject �Ĵ�С���Ժ��� BCryptGenerateSymmetricKey ������ʹ�ô˱���
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] ʧ�ܣ�����Ϊ��0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ��ȡ������ʹ�õĿ�Ĵ�С������ʹ�õ��� AES����˴�СӦΪ 16 �ֽڡ�
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] ʧ�ܣ�����Ϊ��0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // �����С�Ƿ�Ϊ 16 �ֽ�
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // �����������ڴ�
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ��������ģʽ����Ϊ CBC����ʹ�� 32 �ֽڵ���Կ�� 16 �ֽڵ� IV��
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty ʧ�ܣ�����Ϊ��0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ���� AES ��Կ��pAes->pKey�����ɼ���������������ڴ�СΪ cbKeyObject �� pbKeyObject ��
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey ʧ�ܣ�����Ϊ��0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ���� BCryptDecrypt�������������Ϊ NULL���Լ�������������Ĵ�С�������� cbPlainText ��
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] ʧ�ܣ�����Ϊ��0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Ϊ��������������㹻���ڴ棬cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // �ٴ����� BCryptDecrypt��ʹ�� pbPlainText ��Ϊ���������
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] ʧ�ܣ�����Ϊ��0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ����
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE) {
        // ���һ�����������ǽ����� pbPlainText �� cbPlainText
        pAes->pPlainText = pbPlainText;
        pAes->dwPlainSize = cbPlainText;
    }
    return bSTATE;

}

void PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
    printf("%s:", Name);
    for (SIZE_T i = 0; i < Size; ++i) {
        printf("\\x%02X,", Data[i]);
    }
    printf("\n");
}
// ����ʹ�������򵥵� InstallAesDecryption �İ�װ����
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    // ��ʼ���ṹ
    AES Aes = {
        .pKey = pKey,
        .pIv = pIv,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    // �������
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}


// ��ӡ����Ļ����Կ
unsigned char pKey[] = { };

// ��ӡ����Ļ�� iv
unsigned char pIv[] = { };


// ��ӡ����Ļ�ļ��ܻ�����Ϊ��
unsigned char CipherText[] = { };

int main() {

    // �������� SimpleDecryption �е����������������������������Ӧ��С
    PVOID	pPlaintext = NULL;
    DWORD	dwPlainSize = NULL;

    // ����
    if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &pPlaintext, &dwPlainSize)) {
        return -1;
    }

    // ��ʮ�����Ƹ�ʽ���������ݴ�ӡ����Ļ
    PrintHexData("PlainText", pPlaintext, dwPlainSize);

    // ����ӡ����This is a plain text string, we'll try to encrypt/decrypt !��
    printf("Data: %s \n", pPlaintext);

    // ���
    HeapFree(GetProcessHeap(), 0, pPlaintext);
    system("PAUSE");
    return 0;
}




