// �ο����ϣ�
// ../doc/VC++���簲ȫ��̷�����2��-������ǩ��֤��.mht
// ../doc/����֤��
//
// RSA���ԣ�ǩ��ԭ��
// ���� --˽Կ����--> ���� --��Կ����--> ����
// ���� --��Կ����--> ���� --˽Կ����--> ����

/***************************************************************

 * ��  Ŀ������֤��
 * ��  �ܣ�������ǩ������֤��
 * ��  �ߣ�Master.R
 * ��  �ڣ�2013-03-29
 * ��  Ȩ��Copyright (c) 2012-2013 Dream Company
 * ��  ����0.1.0_130329

***************************************************************/

#ifndef _WIN32_WINNT		// ����ʹ���ض��� Windows NT 4.0 ����߰汾�Ĺ��ܡ�
#define _WIN32_WINNT 0x0400	// ����ֵ����Ϊ��Ӧ��ֵ���������� Windows �������汾��
#endif		

#include <stdio.h>
#include <windows.h>
#include <WinCrypt.h>
#pragma comment(lib, "Crypt32.lib")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING) 
#define CERT_SUBJECT_NAME "TEST_SIGNER_NAME"


void HandleError(char *pszErr);	// ��������
HCRYPTPROV GetCryptProv();		// ��ȡ�����ṩ�߾��
void ByteToStr(
			   DWORD cb,
			   void* pv,
			   LPSTR sz);		// ת��BYTE��������Ϊ�ַ���


int main(int argc, char* argv[])
{
	/**�����������ʼ��**/
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

/**
 * �������ܣ���ȡ�����ṩ�߾��
 * ��    ������
 * �� �� ֵ���ɹ�/ʧ��
 **/
HCRYPTPROV GetCryptProv()
{}

/**
 * �������ܣ�ת��BYTE��������Ϊ�ַ���
 * ��    ����
 * �� �� ֵ����
 **/
void ByteToStr(
			   DWORD cb,
			   void* pv,
			   LPSTR sz)
{

}