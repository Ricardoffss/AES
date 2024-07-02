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

} AES, *PAES;

// ����ʵ��
BOOL InstallAesEncryption(PAES pAes) {
    BOOL bSTATE = TRUE;
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;

    ULONG cbResult = 0;
    DWORD dwBlockSize = 0;

    DWORD cbKeyObject = 0;
    PBYTE pbKeyObject = NULL;

    PBYTE pbCipherText = NULL;
    DWORD cbCipherText = 0;

    NTSTATUS STATUS = 0;

    // ��ʼ����hAlgorithm��Ϊ AES �㷨���
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider ����: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ��ȡ��Կ������� pbKeyObject �Ĵ�С�������Խ�������� BCryptGenerateSymmetricKey ����ʹ��
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] ����: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ��� cbKeyObject �Ƿ���Ч
    if (cbKeyObject == 0) {
        printf("[!] Invalid cbKeyObject value.\n");
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // Ϊ��Կ��������ڴ�
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ��ȡ������ʹ�õĿ��С���������� AES�����������Ϊ 16 ���ֽڡ�
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(dwBlockSize), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] ����: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // �����С�Ƿ�Ϊ 16 ���ֽ�
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ���ÿ�����ģʽΪ CBC����ʹ���� 32 �ֽڵ���Կ�� 16 �ֽڵ� IV��
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty ����: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // �� AES ��Կ��pAes->pKey��������Կ��������������� pbKeyObject �У���СΪ cbKeyObject
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey ����: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ��һ������ BCryptEncrypt�����������Ϊ NULL�����ڼ�������������Ĵ�С���ô�С������ cbCipherText ��
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptEncrypt[1] ����: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ����Ϊ��������������㹻���ڴ棨cbCipherText��
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (pbCipherText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // �ٴ����� BCryptEncrypt��pbCipherText ��Ϊ���������
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptEncrypt[2] ����: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // ����
_EndOfFunc:
    if (hKeyHandle) BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbCipherText != NULL && bSTATE) {
        pAes->pCipherText = pbCipherText;
        pAes->dwCipherSize = cbCipherText;
    }
    return bSTATE;
}



// ��װ InstallAesEncryption �ĺ������򻯲���
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

    if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    // ��ʼ���ṹ
    AES Aes = {
        .pKey = pKey,
        .pIv = pIv,
        .pPlainText = pPlainTextData,
        .dwPlainSize = sPlainTextSize
    };

    if (!InstallAesEncryption(&Aes)) {
        return FALSE;
    }

    // �������
    *pCipherTextData = Aes.pCipherText;
    *sCipherTextSize = Aes.dwCipherSize;

    return TRUE;
}

void PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
    printf("%s:", Name);
    for (SIZE_T i = 0; i < Size; ++i) {
        printf("0x%02X,", Data[i]);
    }
    printf("\n");
}

// ���ɴ�СΪ sSize ������ֽ�
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

    int i = 0;
    for (; i < sSize; i++) {
        pByte[i] = (BYTE)rand() % 0xFF;
    }

}

// ���ı�����ʮ�����Ƹ�ʽ����������
// ����ʮ�������е������ַ�����This is a plain text string, we'll try to encrypt/decrypt !��
using char Data [];

int main() {

    BYTE pKey [KEYSIZE];                    // KEYSIZE Ϊ 32 �ֽ�
    BYTE pIv [IVSIZE];                      // IVSIZE Ϊ 16 �ֽ�

    srand(time(NULL));                      // ������Կ�����ӡ������ڽ�һ���������Կ��
    GenerateRandomBytes(pKey, KEYSIZE);     // ʹ�ø�������������Կ

    srand(time(NULL) ^ pKey[0]);            // ���� IV �����ӡ�ʹ����Կ�ĵ�һ���ֽ�����������ԡ�
    GenerateRandomBytes(pIv, IVSIZE);       // ʹ�ø����������� IV

    // ����Կ�� IV ��ӡ������̨��
    PrintHexData("pKey", pKey, KEYSIZE);
    PrintHexData("pIv", pIv, IVSIZE);


    // ���������������������������Ӧ�Ĵ�С������ SimpleEncryption ��ʹ��
    PVOID pCipherText = NULL;
    DWORD dwCipherSize = NULL;

    // ����
    if (!SimpleEncryption(Data, sizeof(Data), pKey, pIv, &pCipherText, &dwCipherSize)) {
        return -1;
    }

    // �����ܺ�Ļ�������ӡΪʮ����������
    PrintHexData("CipherText", pCipherText, dwCipherSize);

    // ���
    HeapFree(GetProcessHeap(), 0, pCipherText);
    system("PAUSE");
    return 0;
}
