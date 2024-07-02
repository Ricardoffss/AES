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

	PBYTE	pPlainText;         // 明文数据的基地址
	DWORD	dwPlainSize;        // 明文数据的大小

	PBYTE	pCipherText;        // 密文数据的基地址
	DWORD	dwCipherSize;       // 密文数据的大小（如果填充了数据，这个值可能不同于 dwPlainSize）

	PBYTE	pKey;               // 32 字节密钥
	PBYTE	pIv;                // 16 字节 IV（初始化向量）

} AES, *PAES;

// 加密实现
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

    // 初始化“hAlgorithm”为 AES 算法句柄
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider 出错: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 获取密钥对象变量 pbKeyObject 的大小。该属性将被后面的 BCryptGenerateSymmetricKey 函数使用
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(cbKeyObject), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] 出错: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 检查 cbKeyObject 是否有效
    if (cbKeyObject == 0) {
        printf("[!] Invalid cbKeyObject value.\n");
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 为密钥对象分配内存
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 获取加密中使用的块大小。由于这是 AES，因此它必须为 16 个字节。
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(dwBlockSize), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] 出错: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 检查块大小是否为 16 个字节
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 设置块密码模式为 CBC。这使用了 32 字节的密钥和 16 字节的 IV。
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty 出错: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 从 AES 密钥“pAes->pKey”生成密钥对象。输出将保存在 pbKeyObject 中，大小为 cbKeyObject
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey 出错: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 第一次运行 BCryptEncrypt，其输出参数为 NULL，用于检索输出缓冲区的大小，该大小保存在 cbCipherText 中
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptEncrypt[1] 出错: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 重新为输出缓冲区分配足够的内存（cbCipherText）
    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (pbCipherText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 再次运行 BCryptEncrypt，pbCipherText 作为输出缓冲区
    STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptEncrypt[2] 出错: 0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 清理
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



// 封装 InstallAesEncryption 的函数，简化操作
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

    if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    // 初始化结构
    AES Aes = {
        .pKey = pKey,
        .pIv = pIv,
        .pPlainText = pPlainTextData,
        .dwPlainSize = sPlainTextSize
    };

    if (!InstallAesEncryption(&Aes)) {
        return FALSE;
    }

    // 保存输出
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

// 生成大小为 sSize 的随机字节
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

    int i = 0;
    for (; i < sSize; i++) {
        pByte[i] = (BYTE)rand() % 0xFF;
    }

}

// 纯文本，以十六进制格式，将被加密
// 这是十六进制中的以下字符串“This is a plain text string, we'll try to encrypt/decrypt !”
using char Data [];

int main() {

    BYTE pKey [KEYSIZE];                    // KEYSIZE 为 32 字节
    BYTE pIv [IVSIZE];                      // IVSIZE 为 16 字节

    srand(time(NULL));                      // 生成密钥的种子。这用于进一步随机化密钥。
    GenerateRandomBytes(pKey, KEYSIZE);     // 使用辅助函数生成密钥

    srand(time(NULL) ^ pKey[0]);            // 生成 IV 的种子。使用密钥的第一个字节以增加随机性。
    GenerateRandomBytes(pIv, IVSIZE);       // 使用辅助函数生成 IV

    // 将密钥和 IV 打印到控制台上
    PrintHexData("pKey", pKey, KEYSIZE);
    PrintHexData("pIv", pIv, IVSIZE);


    // 定义两个变量输出缓冲区及其相应的大小，将在 SimpleEncryption 中使用
    PVOID pCipherText = NULL;
    DWORD dwCipherSize = NULL;

    // 加密
    if (!SimpleEncryption(Data, sizeof(Data), pKey, pIv, &pCipherText, &dwCipherSize)) {
        return -1;
    }

    // 将加密后的缓冲区打印为十六进制数组
    PrintHexData("CipherText", pCipherText, dwCipherSize);

    // 清除
    HeapFree(GetProcessHeap(), 0, pCipherText);
    system("PAUSE");
    return 0;
}
