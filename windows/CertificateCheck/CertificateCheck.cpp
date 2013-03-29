// CertificateCheck.cpp : �������̨Ӧ�ó������ڵ㡣
// �ο���http://blog.csdn.net/yincheng01/article/details/6845801
// ����֤��ο���
// �˽�����֤�� http://technet.microsoft.com/zh-cn/library/bb123848(v=exchg.65).aspx
// ǳ������֤�� http://www.cnblogs.com/hyddd/archive/2009/01/07/1371292.html
// ����֤���Ӧ�� http://tech.ccidnet.com/art/782/20030222/620577_1.html
// �鿴����֤�� http://tech.ccidnet.com/art/782/20040809/620573_1.html

/***************************************************************

 * ��  Ŀ������֤��
 * ��  ����CertificateCheck.cpp
 * ��  �ܣ�����֤����Ч����֤
 * ��  �ߣ�Master.R
 * ��  �ڣ�2013-03-24
 * ��  Ȩ��Copyright (c) 2012-2013 Dream Company
 * ��  ����1.0.0_130324

***************************************************************/

#ifndef _WIN32_WINNT		// ����ʹ���ض��� Windows XP ����߰汾�Ĺ��ܡ�
#define _WIN32_WINNT 0x0400	// ����ֵ����Ϊ��Ӧ��ֵ���������� Windows �������汾��
#endif		

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>
#include <WinCrypt.h>
#pragma comment(lib, "Crypt32.lib")
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void HandleError(TCHAR *pszErr)
{
	MessageBox(NULL, pszErr, L"����֤����֤����", MB_OK);
}

int _tmain(int argc, _TCHAR* argv[])
{
	/**�����������ʼ��**/
	HCERTSTORE		hSystemStore = NULL;
	PCCERT_CONTEXT	pTargetCert = NULL;
	PCERT_INFO		pTargetCertInfo;
	char			szSubjectName[] = "ABA.ECOM Root CA";	// ֤��������ƣ�Ӧ��֤��֤����֤�������Ч

	/**��ϵͳ֤���**/
	hSystemStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM,			// ϵͳ֤���
			0,								// �������ͣ����ﲻ��Ҫ
			NULL,							// ʹ��Ĭ�ϵ�CSP
			CERT_SYSTEM_STORE_CURRENT_USER,	// ϵͳ��洢λ��
			L"MY");							// ϵͳ������
	if (hSystemStore)
	{
		printf("��ϵͳ֤���ɹ�. MY ֤����Ѿ���. \n");
	}
	else
	{
		DWORD dwErrorCode = GetLastError(); 
		TCHAR pszError[512] = {0};
		swprintf(pszError, sizeof(pszError), L"�򿪸�֤������. Error code[%l]", dwErrorCode);
		HandleError(pszError);
	}

	/**��ϵͳ֤����в�ѯ֤��**/
	pTargetCert = CertFindCertificateInStore(
			hSystemStore,					// ֤�������ϵͳ֤���
			MY_ENCODING_TYPE,				// ��������
			0,								// ����Ҫ���ñ�־λ
			CERT_FIND_SUBJECT_STR_A,		// ���ұ�׼Ϊ��֤���������ΪszSubjectName
			szSubjectName,					// ֤���������
			pTargetCert);					// �ϴβ��ҵ���֤�飬 ��һ�β��ң���֤��⿪ʼλ�ò���
	if (pTargetCert)
	{
		printf("�ҵ��˴�֤��. \n");
	}
	else
	{
		DWORD dwErrorCode = GetLastError(); 
		TCHAR pszError[512] = {0};
		swprintf(pszError, sizeof(pszError), L"δ���ҵ������֤��. Error code[%l]", dwErrorCode);
		HandleError(pszError);
	}

	/**֤����Ч����֤**/
	pTargetCertInfo = pTargetCert->pCertInfo;
	switch(CertVerifyTimeValidity(
			NULL,							// ʹ�õ�ǰʱ��
			pTargetCertInfo))				// ����֤��Ч�ڵ�֤��ָ��
	{
	case -1:
		{
			printf("֤����Ч. \n");
			break;
		}
	case 1:
		{
			printf("֤���ѹ���. \n");
			break;
		}
	case 0:
		{
			printf("֤���ʱ����Ч. \n");
			break;
		}
	}

	if ( CertCloseStore(hSystemStore, 0) )
	{
		printf("�ر�ϵͳ֤���ɹ�.\n");
	}
	else
	{
		DWORD dwErrorCode = GetLastError(); 
		TCHAR pszError[512] = {0};
		swprintf(pszError, sizeof(pszError), L"�رո�֤������. Error code[%l]", dwErrorCode);
		HandleError(pszError);
	}

	getchar();

	return 0;
}

