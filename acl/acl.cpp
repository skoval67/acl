// acl.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "locale.h"
#include "aclapi.h"
#include "atlpath.h"

#pragma warning( disable : 4996 )

#define MAX_DOMAIN_NAME_LEN 255			// макс. длина буфера под имя домена DNS
#define MAX_USERNAME_LEN 127			// макс. длина буфера под имя пользователя
#define MAX_MESSAGE_LEN 512

enum search_regime {owner, dacl, sacl};

struct tparams {
  TCHAR path[MAX_PATH];
  BOOLEAN bRecurseSubdirs;
  enum search_regime tag;
  PSID psidUser;
} params = {0, 0, 0, NULL};

TCHAR message[MAX_MESSAGE_LEN];
BOOLEAN uiRussian;

LPTSTR usage_ru = L"\nПрименение: acl [/r] {/o|/d|/s} username path [2>errors.log]\n\n\
/r рекурсивный поиск в каталоге path\n\
/o поиск файлов, владельцем которых является username\n\
/d поиск файлов, в дискреционных списках контроля доступа которых присутствует username\n\
/s поиск файлов, в системных списках контроля доступа которых присутствует username\n\n\
   Имя пользователя указывается в формате domain\\account, account@dns.domain.name или просто account. Если вместо имени \
пользователя указать *nobody будет выполнен поиск файлов в списках доступа которых есть записи, которым не сопоставлены \
никакие имена.\n\n\
2>errors.log\tнаправить сообщения об ошибках в файл errors.log";

LPTSTR usage_eng = L"\nUsage: acl [/r] {/o|/d|/s} username path [2>errors.log]\n\n\
/r recursive search in the directory path\n\
/o search for files owned by username\n\
/d search files in discretionary access control lists which there is username\n\
/s search files, in system access control lists which there is username\n\n\
   Username is in the form domain\\account, account@dns.domain.name or account. If the username is *nobody will scan the \
files in the access list contain entries that are not mapped to any names.\n\n\
2>errors.log\tsend error messages to a file errors.log";

void SetMessageLang()
{
  int nBuff = GetKeyboardLayoutList(0, NULL);
  HKL* lpList = (HKL*) LocalAlloc(LMEM_FIXED, nBuff * sizeof HKL);

  GetKeyboardLayoutList(nBuff, lpList);
  while (nBuff--) {
    if ( uiRussian = 0x419 == (WORD) lpList[nBuff] ) break;
  };
  LocalFree(lpList);

  if ( uiRussian )
    _wsetlocale(LC_ALL, L"Russian");
  
  return;
}

BOOLEAN PathExists(LPTSTR path)
{
  WIN32_FIND_DATA FindFileData;
  HANDLE hFile = FindFirstFile(path, &FindFileData);

  if (hFile == INVALID_HANDLE_VALUE)
    return false;
  FindClose(hFile);
//  wprintf(L"dwFileAttributes - %x\n", FindFileData.dwFileAttributes);
  return ((FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY);
}

BOOLEAN CheckUsername(LPTSTR username, tparams *par)
{
  DWORD dwsid = 0;
  DWORD dwdomain = 0;
  SID_NAME_USE eUse = SidTypeUnknown;
  TCHAR DomainName[MAX_DOMAIN_NAME_LEN];
  
  if (wcscmp(wcsupr(username), L"*NOBODY") == 0) {
    par->psidUser = NULL;
    return true;
  };
  
  LookupAccountName(NULL, username, NULL, &dwsid, NULL, &dwdomain, &eUse);
  if (dwdomain >= MAX_DOMAIN_NAME_LEN) {
    SetLastError(1212);                   // ERROR_INVALID_DOMAINNAME
    return false; };

  par->psidUser = LocalAlloc(LPTR, dwsid);

  return LookupAccountName(NULL, username, par->psidUser, &dwsid, DomainName, &dwdomain, &eUse);
}

BOOLEAN SetPrivilege(BOOLEAN bEnablePrivilege)
{
  TOKEN_PRIVILEGES tp;
  LUID luid;
  HANDLE hToken;

  if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
	GetLastError();
  if ( !LookupPrivilegeValue( 
        NULL,				// lookup privilege on local system
        SE_SECURITY_NAME,   // privilege to lookup 
        &luid ) )			// receives LUID of privilege
    return FALSE; 

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  if (bEnablePrivilege)
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  else
    tp.Privileges[0].Attributes = 0;

  return ( ERROR_SUCCESS == AdjustTokenPrivileges(
       hToken, 
       FALSE, 
       &tp, 
       sizeof(TOKEN_PRIVILEGES), 
       (PTOKEN_PRIVILEGES) NULL, 
       (PDWORD) NULL) );
}

BOOLEAN parse_cmd_line(int argc, _TCHAR* argv[], LPTSTR str, tparams *par)
{
  LPVOID lpMsgBuf;
  DWORD pos = 1;

  if ( uiRussian )
	wcscpy_s(str, MAX_MESSAGE_LEN*2, usage_ru);
  else
    wcscpy_s(str, MAX_MESSAGE_LEN*2, usage_eng);

  if (argc == 1 || argc == 2 && wcscmp(wcsupr(argv[1]), L"/H") == 0)
    return false;

  if ( uiRussian )
	LoadString(GetModuleHandle(NULL), IDS_HELP_RU, str, MAX_MESSAGE_LEN);
  else
	LoadString(GetModuleHandle(NULL), IDS_HELP_ENG, str, MAX_MESSAGE_LEN);

  if (!StrCmp(wcsupr(argv[pos]), L"/R")) {
    par->bRecurseSubdirs = true;
	pos++;
  }

  if (!StrCmp(wcsupr(argv[pos]), L"/O"))
    par->tag = owner;
  else if (!StrCmp(wcsupr(argv[pos]), L"/D"))
    par->tag = dacl;
  else if (!StrCmp(wcsupr(argv[pos]), L"/S"))
    par->tag = sacl;
  else
    return false;

  if (!CheckUsername(argv[++pos], par)) {
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL,
      GetLastError(),
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      (LPTSTR) &lpMsgBuf, 0, NULL );
    wcscpy_s(str, 127, (LPTSTR) lpMsgBuf);
    LocalFree(lpMsgBuf);
    return false; };

  if (!PathExists(argv[++pos])) {
    if ( uiRussian )
	  LoadString(GetModuleHandle(NULL), IDS_DIRNOTFOUND_RU, str, MAX_MESSAGE_LEN);
	else
	  LoadString(GetModuleHandle(NULL), IDS_DIRNOTFOUND_ENG, str, MAX_MESSAGE_LEN);
    return false; 
  };
  
  wcscpy_s(par->path, MAX_PATH, argv[pos]);
  
  return true;
}

BOOLEAN SearchDACL(PACL pacl, PSID psid)
{
  LPVOID pAce = NULL;

  for (DWORD i = 0; i < pacl->AceCount; i++) {
    if (!GetAce(pacl, i, &pAce))
      throw 1;
    if ( EqualSid(&((ACCESS_ALLOWED_ACE *) pAce)->SidStart, psid) )
      return true;
  };

  return false;
}

BOOLEAN SearchSACL(PACL pacl, PSID psid)
{
  LPVOID pAce = NULL;

  for (DWORD i = 0; i < pacl->AceCount; i++) {
    if (!GetAce(pacl, i, &pAce))
      throw 1;
    if ( EqualSid(&((SYSTEM_AUDIT_ACE *) pAce)->SidStart, psid) )
      return true;
  };

  return false;
}

BOOLEAN UnrefACLinDACL(PACL pacl)
{
  LPVOID pAce = NULL;
  DWORD dwName;
  DWORD dwDomainName;
  TCHAR Name[MAX_USERNAME_LEN];
  TCHAR DomainName[MAX_DOMAIN_NAME_LEN];
  SID_NAME_USE eUse = SidTypeUnknown;

  for (DWORD i = 0; i < pacl->AceCount; i++) {
    if (!GetAce(pacl, i, &pAce))
      throw 1;
 	dwName = 0;
	dwDomainName = 0;
	LookupAccountSid(NULL, &((ACCESS_ALLOWED_ACE *) pAce)->SidStart, NULL, &dwName, NULL, &dwDomainName, &eUse);
    if (!LookupAccountSid(NULL, &((ACCESS_ALLOWED_ACE *) pAce)->SidStart, Name, &dwName, DomainName, &dwDomainName, &eUse))
      return true;
  };

  return false;
}

BOOLEAN UnrefACLinSACL(PACL pacl)
{
  LPVOID pAce = NULL;
  DWORD dwName;
  DWORD dwDomainName;
  TCHAR Name[MAX_USERNAME_LEN];
  TCHAR DomainName[MAX_DOMAIN_NAME_LEN];
  SID_NAME_USE eUse = SidTypeUnknown;

  for (DWORD i = 0; i < pacl->AceCount; i++) {
    if (!GetAce(pacl, i, &pAce))
      throw 1;
	dwName = 0;
    dwDomainName = 0;
    LookupAccountSid(NULL, &((SYSTEM_AUDIT_ACE *) pAce)->SidStart, NULL, &dwName, NULL, &dwDomainName, &eUse);
    if (!LookupAccountSid(NULL, &((SYSTEM_AUDIT_ACE *) pAce)->SidStart, Name, &dwName, DomainName, &dwDomainName, &eUse))
      return true;
  };

  return false;
}

BOOLEAN UnrefSID(PSID psidUser) {
  DWORD dwName = 0;
  DWORD dwDomainName = 0;
  TCHAR Name[MAX_USERNAME_LEN];
  TCHAR DomainName[MAX_DOMAIN_NAME_LEN];
  SID_NAME_USE eUse = SidTypeUnknown;
  
  LookupAccountSid(NULL, psidUser, NULL, &dwName, NULL, &dwDomainName, &eUse);
  return !LookupAccountSid(NULL, psidUser, Name, &dwName, DomainName, &dwDomainName, &eUse);
}

LPTSTR FullPath(LPTSTR fname)
{
  DWORD buflen = GetFullPathName(fname, 0, NULL, NULL);
  LPTSTR buffer = (LPTSTR) LocalAlloc(LMEM_FIXED, 2*buflen);
  GetFullPathName(fname, buflen, buffer, NULL);
  return buffer;
}
      
void ScanPathCallBack(LPTSTR filename)
{
  SECURITY_INFORMATION options = OWNER_SECURITY_INFORMATION;
  PSECURITY_DESCRIPTOR pSD = NULL;
  PSID pSidOwner = NULL;
  PACL pDACL = NULL, pSACL = NULL;
  LPVOID lpMsgBuf;
  LPVOID pAce = NULL;
  BOOLEAN found = false;
  LPTSTR buffer;

  try {
   
    if (params.tag == dacl)
      options = DACL_SECURITY_INFORMATION;
	else if (params.tag == sacl)
      options = SACL_SECURITY_INFORMATION;
    
    if (GetNamedSecurityInfo(filename,
                  SE_FILE_OBJECT,
                  options,
                  &pSidOwner,
                  NULL,
                  &pDACL,
                  &pSACL,
                  &pSD))
	  throw 1;

	if (params.tag == owner) {
      if (params.psidUser) 
        found = EqualSid(pSidOwner, params.psidUser);
      else 
        found = UnrefSID(pSidOwner);   // nobody
	  } else if (params.tag == dacl) {
      if (params.psidUser)
        found = BOOLEAN(pDACL) && SearchDACL(pDACL, params.psidUser);
      else
        found = BOOLEAN(pDACL) && UnrefACLinDACL(pDACL);
	} else {
	  if (params.psidUser)
		found = BOOLEAN(pSACL) && SearchSACL(pSACL, params.psidUser);
	  else
	    found = BOOLEAN(pSACL) && UnrefACLinSACL(pSACL);
	};

    if (found) {
      wprintf(L"%s\n", buffer = FullPath(filename));
      LocalFree(buffer);
    };

//	if (pSACL) LocalFree(pSACL);
//	LocalFree(pDACL);
    if (pSD) LocalFree(pSD);
//	if (pSidOwner) LocalFree(pSidOwner);
  }
  catch(int ) {
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        GetLastError(),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );
	  fwprintf(stderr, TEXT("%s - %s\n"), buffer = FullPath(filename), lpMsgBuf);
	  LocalFree(lpMsgBuf);
	  LocalFree(buffer);
  }
}

void ScanPath(TCHAR *rep)
{
  WIN32_FIND_DATA FindFileData; 
  TCHAR path[MAX_PATH];		  
  HANDLE hFind;				  
  DWORD a = 0;				  

  wcsncpy_s(path, MAX_PATH, rep, MAX_PATH - 1 );
  wcsncat_s(path, MAX_PATH, TEXT("\\*.*"), MAX_PATH - wcslen(path) - 1 );

  hFind = FindFirstFile((LPCTSTR) path, &FindFileData);
  if (hFind==INVALID_HANDLE_VALUE)
    return;

  if (wcscmp(FindFileData.cFileName, L".")!=0 && wcscmp(FindFileData.cFileName, L"..")!=0)
  {
    wcsncpy_s(path, MAX_PATH, rep, MAX_PATH - 1 );
    wcsncat_s(path, MAX_PATH, L"\\", MAX_PATH - wcslen(path) - 1 );
    wcsncat_s(path, MAX_PATH, FindFileData.cFileName, MAX_PATH - wcslen(path) - 1 );		
    ScanPath( path );		
  }
  
  while (a != ERROR_NO_MORE_FILES )
  {
    if (!FindNextFile(hFind, &FindFileData))
      a = GetLastError();
    else
	{
      if (wcscmp(FindFileData.cFileName, L".")!=0 && wcscmp(FindFileData.cFileName, L"..")!=0)
      {
        wcsncpy_s( path, MAX_PATH, rep, MAX_PATH - 1 );
        wcsncat_s( path, MAX_PATH, L"\\", MAX_PATH - wcslen(path) - 1 );
        wcsncat_s( path, MAX_PATH, FindFileData.cFileName, MAX_PATH - wcslen(path) - 1 );

        if ( (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY ) {
		  if ( params.bRecurseSubdirs ) ScanPath(path); 
		} else
		  ScanPathCallBack(path);
      }
    }
  }
  FindClose(hFind);
}

void free_buf(const tparams *par)
{
  LocalFree(par->psidUser);
}

int _tmain(int argc, _TCHAR* argv[])
{
  SetMessageLang();

  if (parse_cmd_line(argc, argv, message, &params)) {
    if (params.tag == sacl) SetPrivilege(true);
    ScanPath(params.path);
    if (params.tag == sacl) SetPrivilege(false);
	free_buf(&params);
  } else
    wprintf_s(L"%s\n", message);

  return 0;
}