#define _WIN32_DCOM

#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

unsigned int copyArr(void* dst, size_t dstlength, const void* src, size_t srclength) {
    if (!srclength)
        return 0;
    if (!src)
        return 22;
    if (!dst)
        return 22;
    if (src && dstlength >= srclength)
    {
        memcpy(dst, src, srclength);
        return 0;
    }
    memset(dst, 0, dstlength);
    return 34;
}

int main(int argc, char* argv[])
{
    cout << "\nCommand-line arguments:\n";
    for (int count = 0; count < argc; count++)
        cout << "  argv[" << count << "]   "
        << argv[count] << "\n";

    unsigned long long data = 0x46281003;
    if (argc == 2) {
        data = strtoul(argv[1], NULL, 10);
    }
    else if (argc == 3) {
        data = strtoul(argv[1], NULL, 10) * 0x1000000 | strtoul(argv[2], NULL, 10) * 0x10000 | 0x1003;
    }
    printf("data:%llu(0x%llx)\n", data, data);

    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x"
            << hex << hres << endl;
        return 1;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM negotiates service
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {
        cout << "Failed to initialize security. Error code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;                      // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object. "
            << "Err code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;                 // Program has failed.
    }

    // Step 4: ---------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    // Connect to the local root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\WMI"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );

    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x"
            << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return 1;                // Program has failed.
    }

    cout << "Connected to ROOT\\WMI WMI namespace" << endl;


    // Step 5: --------------------------------------------------
    // Set security levels for the proxy ------------------------

    hres = CoSetProxyBlanket(
        pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
        RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
        NULL,                        // Server principal name 
        RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL,                        // client identity
        EOAC_NONE                    // proxy capabilities 
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x"
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----

    // set up to call the Win32_Process::Create method
    BSTR MethodName = SysAllocString(L"OemWMIfun");
    BSTR ClassName = SysAllocString(L"OemWMIMethod");
    BSTR InstanceObjectPath = SysAllocString(L"OemWMIMethod.InstanceName='ACPI\\PNP0C14\\HWMI_0'");

    IWbemClassObject* pClass = NULL;
    hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

    IWbemClassObject* pInParamsDefinition = NULL;
    hres = pClass->GetMethod(MethodName, 0,
        &pInParamsDefinition, NULL);

    IWbemClassObject* pClassInstance = NULL;
    hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

    // Create the values for the in parameters
    VARIANT varCommand;
    varCommand.vt = VT_ARRAY | VT_UI1;
    SAFEARRAYBOUND rgsabound;
    rgsabound.lLbound = 0;
    rgsabound.cElements = 64;
    SAFEARRAY* sa = SafeArrayCreate(VT_UI1, 1, &rgsabound);
    void* ppvData = NULL;
    if (SUCCEEDED(SafeArrayAccessData(sa, &ppvData)) && !copyArr(ppvData, 64, &data, 64)) {
        varCommand.parray = sa;
    }

    // Store the value for the in parameters
    hres = pClassInstance->Put(L"u8Input", 0,
        &varCommand, 0);
    //wprintf(L"The command is: %d %d\n", ppvData, ppvData[0]);

    // Execute Method
    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(InstanceObjectPath, MethodName, 0,
        NULL, pClassInstance, &pOutParams, NULL);

    if (FAILED(hres))
    {
        cout << "Could not execute method. Error code = 0x"
            << hex << hres << endl;
        VariantClear(&varCommand);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        SysFreeString(InstanceObjectPath);
        SafeArrayDestroy(sa);
        pClass->Release();
        pClassInstance->Release();
        pInParamsDefinition->Release();
        if (pOutParams)pOutParams->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // To see what the method returned,
    // use the following code.  The return value will
    // be in &varReturnValue
    VARIANT varReturnValue;
    varReturnValue.vt = VT_ARRAY | VT_UI1;
    hres = pOutParams->Get(_bstr_t(L"u8Output"), 0,
        &varReturnValue, NULL, 0);

    unsigned long long(*returnData)[64] = (unsigned long long(*)[64])(varReturnValue.parray->pvData);
    printf("u8Output:%llu\n", *returnData[0]);


    // Clean up
    //--------------------------
    VariantClear(&varCommand);
    VariantClear(&varReturnValue);
    SysFreeString(ClassName);
    SysFreeString(MethodName);
    SysFreeString(InstanceObjectPath);
    SafeArrayDestroy(sa);
    pClass->Release();
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pOutParams->Release();
    pLoc->Release();
    pSvc->Release();
    CoUninitialize();
    return 0;
}

