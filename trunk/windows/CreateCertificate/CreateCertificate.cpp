// 参考资料：
// ../doc/VC++网络安全编程范例（2）-创建自签名证书.mht
// ../doc/数字证书
//
// RSA特性，签名原理
// 明文 --私钥加密--> 密文 --公钥解密--> 明文
// 明文 --公钥加密--> 密文 --私钥解密--> 明文

/***************************************************************

 * 项  目：数字证书
 * 功  能：创建自签名数字证书
 * 作  者：Master.R
 * 日  期：2013-03-29
 * 版  权：Copyright (c) 2012-2013 Dream Company
 * 版  本：0.1.0_130329

***************************************************************/

#ifndef _WIN32_WINNT		// 允许使用特定于 Windows NT 4.0 或更高版本的功能。
#define _WIN32_WINNT 0x0400	// 将此值更改为相应的值，以适用于 Windows 的其他版本。
#endif		

#include <stdio.h>
#include <windows.h>
#include <WinCrypt.h>
#pragma comment(lib, "Crypt32.lib")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING) 
#define CERT_SUBJECT_NAME "TEST_SIGNER_NAME"


void HandleError(char *pszErr);	// 错误处理函数
HCRYPTPROV GetCryptProv();		// 获取加密提供者句柄
void ByteToStr(
			   DWORD cb,
			   void* pv,
			   LPSTR sz);		// 转换BYTE类型数组为字符串


int main(int argc, char* argv[])
{
	/**变量声明与初始化**/
	HCERTSTORE hCertStore = NULL;
	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKeySign = NULL;
	PCCERT_CONTEXT pCertCtxSign = NULL;

	BYTE *Encrypted = NULL;
	DWORD EncryptedLen = NULL;
	BYTE *Decrypted = NULL;
	DWORD DecryptedLen = NULL;
	DWORD cbNameEncoded;
	BYTE* pbNameEncoded;

	CERT_NAME_BLOB certName = {
		0,
		NULL};

	CERT_RDN_ATTR rgNameAttr[] = {
		"2.5.4.3",
		CERT_RDN_PRINTABLE_STRING,
		strlen(CERT_SUBJECT_NAME),
		(BYTE*)CERT_SUBJECT_NAME};

	return 0;
}


/**
 * 函数功能：输出错误信息，并终止运行
 * 参    数：错误信息
 * 返 回 值：无
 **/
void HandleError(char *pszErr)
{
	printf("程序执行发生错误!\n");
	if (pszErr)
	{
		printf("%s\n",pszErr);
	}
	printf("错误代码为: %x.\n",GetLastError());
	printf("程序终止执行!\n");
	exit(1);
}

/**
 * 函数功能：获取加密提供者句柄
 * 参    数：无
 * 返 回 值：成功/失败
 **/
HCRYPTPROV GetCryptProv()
{}

/**
 * 函数功能：转换BYTE类型数组为字符串
 * 参    数：
 * 返 回 值：无
 **/
void ByteToStr(
			   DWORD cb,
			   void* pv,
			   LPSTR sz)
{

}