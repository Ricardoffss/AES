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

} AES, * PAES;
// 解密实现
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
    // 使用 AES 算法句柄初始化“hAlgorithm”
    STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptOpenAlgorithmProvider 失败，错误为：0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 获取键对象变量 pbKeyObject 的大小。稍后在 BCryptGenerateSymmetricKey 函数中使用此变量
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[1] 失败，错误为：0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 获取加密中使用的块的大小。由于使用的是 AES，因此大小应为 16 字节。
    STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGetProperty[2] 失败，错误为：0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 检查块大小是否为 16 字节
    if (dwBlockSize != 16) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 分配键对象的内存
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (pbKeyObject == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 将块密码模式设置为 CBC。它使用 32 字节的密钥和 16 字节的 IV。
    STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptSetProperty 失败，错误为：0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 根据 AES 密钥“pAes->pKey”生成键对象。输出将保存在大小为 cbKeyObject 的 pbKeyObject 中
    STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptGenerateSymmetricKey 失败，错误为：0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 运行 BCryptDecrypt，将输出参数设为 NULL，以检索输出缓冲区的大小，保存在 cbPlainText 中
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[1] 失败，错误为：0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 为输出缓冲区分配足够的内存，cbPlainText
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (pbPlainText == NULL) {
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 再次运行 BCryptDecrypt，使用 pbPlainText 作为输出缓冲区
    STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!NT_SUCCESS(STATUS)) {
        printf("[!] BCryptDecrypt[2] 失败，错误为：0x%0.8X \n", STATUS);
        bSTATE = FALSE; goto _EndOfFunc;
    }

    // 清理
_EndOfFunc:
    if (hKeyHandle)
        BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm)
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    if (pbKeyObject)
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbPlainText != NULL && bSTATE) {
        // 如果一切正常，我们将保存 pbPlainText 和 cbPlainText
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
// 用于使工作更简单的 InstallAesDecryption 的包装函数
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

    if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
        return FALSE;

    // 初始化结构
    AES Aes = {
        .pKey = pKey,
        .pIv = pIv,
        .pCipherText = pCipherTextData,
        .dwCipherSize = sCipherTextSize
    };

    if (!InstallAesDecryption(&Aes)) {
        return FALSE;
    }

    // 保存输出
    *pPlainTextData = Aes.pPlainText;
    *sPlainTextSize = Aes.dwPlainSize;

    return TRUE;
}


// 打印到屏幕的密钥
unsigned char pKey[] = { };

// 打印到屏幕的 iv
unsigned char pIv[] = { };


// 打印到屏幕的加密缓冲区为：
unsigned char CipherText[] = { };

int main() {

    // 定义用于 SimpleDecryption 中的两个变量，即输出缓冲区及其相应大小
    PVOID	pPlaintext = NULL;
    DWORD	dwPlainSize = NULL;

    // 解密
    if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &pPlaintext, &dwPlainSize)) {
        return -1;
    }

    // 以十六进制格式将解密数据打印到屏幕
    PrintHexData("PlainText", pPlaintext, dwPlainSize);

    // 将打印：“This is a plain text string, we'll try to encrypt/decrypt !”
    printf("Data: %s \n", pPlaintext);

    // 清除
    HeapFree(GetProcessHeap(), 0, pPlaintext);
    system("PAUSE");
    return 0;
}




