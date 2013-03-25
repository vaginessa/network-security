// CertificateCheck.cpp : 定义控制台应用程序的入口点。
// 参考：http://blog.csdn.net/yincheng01/article/details/6845801
// 数字证书参考：
// http://technet.microsoft.com/zh-cn/library/bb123848(v=exchg.65).aspx
// http://www.cnblogs.com/hyddd/archive/2009/01/07/1371292.html
// http://blog.csdn.net/program_think/article/details/5300184
// http://tech.ccidnet.com/art/782/20030222/620577_1.html
// http://tech.ccidnet.com/art/782/20040809/620573_1.html

/***************************************************************

 * 项  目：数字证书
 * 文  件：CertificateCheck.cpp
 * 功  能：数字证书有效期验证
 * 作  者：Master.R
 * 日  期：2013-03-24
 * 版  权：Copyright (c) 2012-2013 Dream Company
 * 版  本：1.0.0_130324

***************************************************************/

#include "stdafx.h"
#include <Windows.h>
#include <WinCrypt.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void HandleError(TCHAR *pszErr)
{
	MessageBox(NULL, pszErr, L"数字证书验证错误", MB_OK);
}

int _tmain(int argc, _TCHAR* argv[])
{
	/**变量声明与初始化**/
	HCERTSTORE		hSystemStore = NULL;
	PCCERT_CONTEXT	pTargetCert = NULL;
	PCERT_INFO		pTargetCertInfo;
	char			szSubjectName[] = "ABA.ECOM Root CA";	// 证书客体名称，应保证此证书在证书库中有效

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
		DWORD dwErrorCode = GetLastError(); 
		TCHAR pszError[512] = {0};
		swprintf(pszError, sizeof(pszError), L"打开根证书库出错. Error code[%l]", dwErrorCode);
		HandleError(pszError);
	}

	/**在系统证书库中查询证书**/
	pTargetCert = CertFindCertificateInStore(
			hSystemStore,					// 证书库句柄，系统证书库
			MY_ENCODING_TYPE,				// 编码类型
			0,								// 不需要设置标志位
			CERT_FIND_SUBJECT_STR_A,		// 查找标准为：证书客体名称为szSubjectName
			szSubjectName,					// 证书客体名称
			pTargetCert);					// 上次查找到的证书， 第一次查找，从证书库开始位置查找
	if (pTargetCert)
	{
		printf("找到了此证书. \n");
	}
	else
	{
		DWORD dwErrorCode = GetLastError(); 
		TCHAR pszError[512] = {0};
		swprintf(pszError, sizeof(pszError), L"未能找到所需的证书. Error code[%l]", dwErrorCode);
		HandleError(pszError);
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
		DWORD dwErrorCode = GetLastError(); 
		TCHAR pszError[512] = {0};
		swprintf(pszError, sizeof(pszError), L"关闭根证书库出错. Error code[%l]", dwErrorCode);
		HandleError(pszError);
	}

	return 0;
}

