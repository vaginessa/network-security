// 参考资料：
// ../doc/VC++网络安全编程范例（1）--数字证书有效期验证.mht
// ../doc/数字证书

/***************************************************************

 * 项  目：数字证书
 * 功  能：验证数字证书有效期
 * 作  者：Master.R
 * 日  期：2013-03-24
 * 版  权：Copyright (c) 2012-2013 Dream Company
 * 版  本：0.2.0_130324

***************************************************************/

#ifndef _WIN32_WINNT		// 允许使用特定于 Windows NT 4.0 或更高版本的功能。
#define _WIN32_WINNT 0x0400	// 将此值更改为相应的值，以适用于 Windows 的其他版本。
#endif

#include <stdio.h>
#include <Windows.h>
#include <WinCrypt.h>
#pragma comment(lib, "Crypt32.lib")
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


void HandleError(char *pszErr);	// 错误处理函数


int main(int argc, char* argv[])
{
	/**变量声明与初始化**/
	HCERTSTORE		hSystemStore = NULL;
	PCCERT_CONTEXT	pTargetCert = NULL;
	PCERT_INFO		pTargetCertInfo;
	char			szSubjectName[] = "ABA.ECOM Root CA";	// 证书客体名称，应保证此证书在证书库中有效

	CERT_INFO		targetCertInfo;

	/**打开系统证书库**/
	hSystemStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,			// 系统证书库
			0,								// 编码类型，这里不需要
			NULL,							// 使用默认的CSP
			CERT_SYSTEM_STORE_CURRENT_USER,	// 系统库存储位置
			L"MY");							// 系统库名称
	if (hSystemStore)
	{
		printf("打开系统证书库成功. MY 证书库已经打开. \n");
	}
	else
	{
		HandleError("打开根证书库出错.");
	}

	/**查找系统证书库中第一个证书**/
	pTargetCert = CertEnumCertificatesInStore(hSystemStore, pTargetCert);
	targetCertInfo.Issuer = pTargetCert->pCertInfo->Issuer;
	targetCertInfo.SerialNumber = pTargetCert->pCertInfo->SerialNumber;

	/**在系统证书库中查询证书**/
	pTargetCert = CertFindCertificateInStore(
			hSystemStore,					// 证书库句柄，系统证书库
			MY_ENCODING_TYPE,				// 编码类型
			0,								// 不需要设置标志位
			CERT_FIND_SUBJECT_CERT,			// 查找标准为：CERT_INFO's issuer and serial number 
			&targetCertInfo,					// CERT_INFO
			NULL);							// 上次查找到的证书， 第一次查找，从证书库开始位置查找
	if (pTargetCert)
	{
		printf("找到了此证书. \n");
	}
	else
	{
		HandleError("未能找到所需的证书.");
	}

	/**证书有效期验证**/
	pTargetCertInfo = pTargetCert->pCertInfo;
	switch(CertVerifyTimeValidity(
			NULL,							// 使用当前时间
			pTargetCertInfo))				// 欲验证有效期的证书指针
	{
	case -1:
		{
			printf("证书无效. \n");
			break;
		}
	case 1:
		{
			printf("证书已过期. \n");
			break;
		}
	case 0:
		{
			printf("证书的时间有效. \n");
			break;
		}
	}

	if ( CertCloseStore(hSystemStore, 0) )
	{
		printf("关闭系统证书库成功.\n");
	}
	else
	{
		HandleError("关闭根证书库出错.");
	}

	getchar();

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
