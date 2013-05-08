// �ο����ϣ�
// ../doc/VC++���簲ȫ��̷�����1��--����֤����Ч����֤.mht
// ../doc/����֤��

/***************************************************************

 * ��  Ŀ������֤��
 * ��  �ܣ���֤����֤����Ч��
 * ��  �ߣ�Master.R
 * ��  �ڣ�2013-03-24
 * ��  Ȩ��Copyright (c) 2012-2013 Dream Company
 * ��  ����0.2.0_130324

***************************************************************/

#ifndef _WIN32_WINNT		// ����ʹ���ض��� Windows NT 4.0 ����߰汾�Ĺ��ܡ�
#define _WIN32_WINNT 0x0400	// ����ֵ����Ϊ��Ӧ��ֵ���������� Windows �������汾��
#endif

#include <stdio.h>
#include <Windows.h>
#include <WinCrypt.h>
#pragma comment(lib, "Crypt32.lib")
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)


void HandleError(char *pszErr);	// ��������


int main(int argc, char* argv[])
{
	/**�����������ʼ��**/
	HCERTSTORE		hSystemStore = NULL;
	PCCERT_CONTEXT	pTargetCert = NULL;
	PCERT_INFO		pTargetCertInfo;
	char			szSubjectName[] = "ABA.ECOM Root CA";	// ֤��������ƣ�Ӧ��֤��֤����֤�������Ч

	CERT_INFO		targetCertInfo;

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
		HandleError("�򿪸�֤������.");
	}

	/**����ϵͳ֤����е�һ��֤��**/
	pTargetCert = CertEnumCertificatesInStore(hSystemStore, pTargetCert);
	targetCertInfo.Issuer = pTargetCert->pCertInfo->Issuer;
	targetCertInfo.SerialNumber = pTargetCert->pCertInfo->SerialNumber;

	/**��ϵͳ֤����в�ѯ֤��**/
	pTargetCert = CertFindCertificateInStore(
			hSystemStore,					// ֤�������ϵͳ֤���
			MY_ENCODING_TYPE,				// ��������
			0,								// ����Ҫ���ñ�־λ
			CERT_FIND_SUBJECT_CERT,			// ���ұ�׼Ϊ��CERT_INFO's issuer and serial number 
			&targetCertInfo,					// CERT_INFO
			NULL);							// �ϴβ��ҵ���֤�飬 ��һ�β��ң���֤��⿪ʼλ�ò���
	if (pTargetCert)
	{
		printf("�ҵ��˴�֤��. \n");
	}
	else
	{
		HandleError("δ���ҵ������֤��.");
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
		HandleError("�رո�֤������.");
	}

	getchar();

	return 0;
}


/**
 * �������ܣ����������Ϣ������ֹ����
 * ��    ����������Ϣ
 * �� �� ֵ����
 **/
void HandleError(char *pszErr)
{
	printf("����ִ�з�������!\n");
	if (pszErr)
	{
		printf("%s\n",pszErr);
	}
	printf("�������Ϊ: %x.\n",GetLastError());
	printf("������ִֹ��!\n");
	exit(1);
}
