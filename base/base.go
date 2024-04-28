package base

/*
#cgo linux LDFLAGS: -ldl
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <swsds.h>

#include <dlfcn.h>

struct LibHandle {
	void *handle;
};

struct LibHandle *NewLib2(const char *iLibrary)
{
	struct LibHandle *h = calloc(1,sizeof(struct LibHandle));
	h->handle = dlopen(iLibrary,1);
	if(h->handle == NULL){
		free(h);
		return NULL;
	}
	return h;
}

void DestroyLib2(struct LibHandle *h)
{
	if (!h) {
		return;
	}
	if (h->handle == NULL) {
		return;
	}
	if (dlclose(h->handle) < 0) {
		return;
	}
	free(h);
}

// *** 设备管理类函数 ***
// 1.打开设备
SGD_RV SDFOpenDevice2(struct LibHandle * h, SGD_HANDLE *phDeviceHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_OpenDevice");
	return (*fptr)(phDeviceHandle);
}
// 2.关闭设备
SGD_RV SDFCloseDevice2(struct LibHandle * h,SGD_HANDLE hDeviceHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CloseDevice");
	return (*fptr)(hDeviceHandle);
}
// 3.创建会话
SGD_RV SDFOpenSession2(struct LibHandle * h,SGD_HANDLE hDeviceHandle, SGD_HANDLE *phSessionHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE,SGD_HANDLE *);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_OpenSession");
	return (*fptr)(hDeviceHandle,phSessionHandle);
}
// 4.关闭会话
SGD_RV SDFCloseSession2(struct LibHandle * h,SGD_HANDLE hSessionHandle)
{
    typedef SGD_RV (*FPTR)(SGD_HANDLE);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_CloseSession");
	return (*fptr)(hSessionHandle);
}

// *** 密码卡管理函数 ***

// 5.初始化设备
SGD_RV SWCSMInitDevice(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiFlag)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_InitDevice");
	return (*fptr)(hSessionHandle, uiFlag);
}

// 12.产生内部ECC密钥对
SGD_RV SWCSMGenerateECCKeyPair(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_GenerateECCKeyPair");
	return (*fptr)(hSessionHandle, uiKeyNumber);
}

// 13.导入ECC密钥对
SGD_RV SWCSMImportECCKeyPair(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber, ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32, ECCrefPublicKey*, ECCrefPrivateKey*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_ImportECCKeyPair");
	return (*fptr)(hSessionHandle, uiKeyNumber, pucPublicKey, pucPrivateKey);
}

// 14.销毁内部ECC密钥对
SGD_RV SWCSMDestroyECCKeyPair(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyNumber)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_DestroyECCKeyPair");
	return (*fptr)(hSessionHandle, uiKeyNumber);
}

// 15.获取密码设备内部密钥状态
SGD_RV SDFGetKeyStatus(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount) {
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32, SGD_UINT32*, SGD_UINT32*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SDF_GetKeyStatus");
	return (*fptr)(hSessionHandle, uiKeyType, puiKeyStatus, puiKeyCount);
}

// 16.备份初始化
SGD_RV SWCSMBackupInitNoIC(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgorithmID, SGD_UCHAR *passwd, SGD_UINT32 uiPwdLength)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32, SGD_UCHAR*, SGD_UINT32);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_BackupInit_NoIC");
	return (*fptr)(hSessionHandle, uiAlgorithmID, passwd, uiPwdLength);
}

// 18.备份导出ECC密钥对
SGD_RV SWCSMBackupExportECCKey(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiIndex, SGD_UINT32 *puiKeyBits, SGD_UCHAR *pucKeyData, SGD_UINT32 *puiKeyDataLength)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32, SGD_UINT32*, SGD_UCHAR*, SGD_UINT32*);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_BackupExportECCKey");
	return (*fptr)(hSessionHandle, uiIndex, puiKeyBits, pucKeyData, puiKeyDataLength);
}

// 20.备份结束
SGD_RV SWCSMBackupFinal(struct LibHandle * h, SGD_HANDLE hSessionHandle)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_BackupFinal");
	return (*fptr)(hSessionHandle);
}

// 21.恢复初始化
SGD_RV SWCSMRestoreInitNoIC(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiAlgorithmID, SGD_UCHAR *passwd, SGD_UINT32 uiPwdLength)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32, SGD_UCHAR*, SGD_UINT32);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_RestoreInit_NoIC");
	return (*fptr)(hSessionHandle, uiAlgorithmID, passwd, uiPwdLength);
}

// 23.恢复导入ECC密钥对
SGD_RV SWCSMRestoreImportECCKey(struct LibHandle * h, SGD_HANDLE hSessionHandle, SGD_UINT32 uiIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucKeyData, SGD_UINT32 uiKeyDataLength)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE, SGD_UINT32, SGD_UINT32, SGD_UCHAR*, SGD_UINT32);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_RestoreImportECCKey");
	return (*fptr)(hSessionHandle, uiIndex, uiKeyBits, pucKeyData, uiKeyDataLength);
}

// 25.恢复结束
SGD_RV SWCSMRestoreFinal(struct LibHandle * h, SGD_HANDLE hSessionHandle)
{
	typedef SGD_RV (*FPTR)(SGD_HANDLE);
	FPTR fptr = (FPTR)dlsym(h->handle, "SWCSM_RestoreFinal");
	return (*fptr)(hSessionHandle);
}

*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/pingcap/errors"
	"github.com/tjfoc/gmsm/sm2"
)

func New(libPath string) *Ctx {
	c := new(Ctx)
	mod := C.CString(libPath)
	defer C.free(unsafe.Pointer(mod))
	c.libHandle = C.NewLib2(mod)
	if c.libHandle == nil {
		return nil
	}
	return c
}

func ToError(e C.SGD_RV) error {
	if e == C.SDR_OK {
		return nil
	}
	return fmt.Errorf("sdf: 0x%X", uint(e))
}

type Ctx struct {
	libHandle *C.struct_LibHandle
}

type SessionHandle C.SGD_HANDLE

var stubData = []byte{0}

func ToUCharPtr(data []byte) (dataPtr *C.SGD_UCHAR) {
	l := len(data)
	if l == 0 {
		data = stubData
	}
	dataPtr = (*C.SGD_UCHAR)(unsafe.Pointer(&data[0]))
	return dataPtr
}

func ConvertToECCrefPrivateKeyC(privateKey *sm2.PrivateKey) (pucPrivateKey C.ECCrefPrivateKey) {
	pucPrivateKey.bits = C.ECCref_MAX_BITS
	dBytes := privateKey.D.Bytes()
	for i := 0; i < len(dBytes); i++ {
		pucPrivateKey.D[i] = C.SGD_UCHAR(dBytes[i])
	}
	return pucPrivateKey
}

func ConvertToECCrefPublicKeyC(publicKey *sm2.PublicKey) (pucPublicKey C.ECCrefPublicKey) {
	pucPublicKey.bits = C.ECCref_MAX_BITS
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()
	for i := 0; i < len(xBytes); i++ {
		pucPublicKey.x[i] = C.SGD_UCHAR(xBytes[i])
	}
	for i := 0; i < len(yBytes); i++ {
		pucPublicKey.y[i] = C.SGD_UCHAR(yBytes[i])
	}
	return pucPublicKey
}

func (c *Ctx) Destroy() {
	C.DestroyLib2(c.libHandle)
}

// SDFOpenDevice 1.打开设备
func (c *Ctx) SDFOpenDevice() (deviceHandle SessionHandle, err error) {
	var rv C.SGD_RV
	var dH C.SGD_HANDLE
	rv = C.SDFOpenDevice2(c.libHandle, &dH)
	deviceHandle = SessionHandle(dH)
	return deviceHandle, ToError(rv)
}

// SDFCloseDevice 2.关闭设备
func (c *Ctx) SDFCloseDevice(deviceHandle SessionHandle) (err error) {
	var rv = C.SDFCloseDevice2(c.libHandle, C.SGD_HANDLE(deviceHandle))
	return ToError(rv)
}

// SDFOpenSession 3.创建会话
func (c *Ctx) SDFOpenSession(deviceHandle SessionHandle) (SessionHandle, error) {
	var s C.SGD_HANDLE
	var rv = C.SDFOpenSession2(c.libHandle, C.SGD_HANDLE(deviceHandle), &s)
	return SessionHandle(s), ToError(rv)
}

// SDFCloseSession 4.关闭会话
func (c *Ctx) SDFCloseSession(sessionHandle SessionHandle) error {
	var err = C.SDFCloseSession2(c.libHandle, C.SGD_HANDLE(sessionHandle))
	return ToError(err)
}

// SWCSMInitDevice 5.初始化设备
func (c *Ctx) SWCSMInitDevice(sessionHandle SessionHandle) error {
	var uiFlag int = 1
	var rv = C.SWCSMInitDevice(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(uiFlag))
	return ToError(rv)
}

// SWCSMGenerateECCKeyPair 12.产生内部ECC密钥对
func (c *Ctx) SWCSMGenerateECCKeyPair(sessionHandle SessionHandle, keyIndex uint32) error {
	var rv = C.SWCSMGenerateECCKeyPair(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex))
	return ToError(rv)
}

// SWCSMImportECCKeyPair 13.导入ECC密钥对
func (c *Ctx) SWCSMImportECCKeyPair(sessionHandle SessionHandle, keyIndex uint32, privateKey *sm2.PrivateKey) error {
	privKey := ConvertToECCrefPrivateKeyC(privateKey)
	pubKey := ConvertToECCrefPublicKeyC(&privateKey.PublicKey)

	var rv = C.SWCSMImportECCKeyPair(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), &pubKey, &privKey)
	return ToError(rv)
}

// SWCSMDestroyECCKeyPair 14.销毁内部ECC密钥对
func (c *Ctx) SWCSMDestroyECCKeyPair(sessionHandle SessionHandle, keyIndex uint32) error {
	var rv = C.SWCSMDestroyECCKeyPair(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex))
	return ToError(rv)
}

// SDFGetKeyStatus 15.获取密码设备内部密钥状态
func (c *Ctx) SDFGetKeyStatus(sessionHandle SessionHandle, keyType KeyType) (keyStatus []uint32, maxKeyCount uint32, err error) {
	keyStatus = make([]uint32, 1000)
	var rv = C.SDFGetKeyStatus(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyType),
		(*C.SGD_UINT32)(unsafe.Pointer(&keyStatus[0])), (*C.SGD_UINT32)(unsafe.Pointer(&maxKeyCount)))
	if err = ToError(rv); err != nil {
		return
	}

	if maxKeyCount <= uint32(len(keyStatus)) {
		keyStatus = keyStatus[:maxKeyCount]
		return
	}

	keyStatus = make([]uint32, maxKeyCount)
	rv = C.SDFGetKeyStatus(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyType),
		(*C.SGD_UINT32)(unsafe.Pointer(&keyStatus[0])), (*C.SGD_UINT32)(unsafe.Pointer(&maxKeyCount)))
	err = ToError(rv)
	return
}

// SWCSMBackupInitNoIC 16.备份初始化
func (c *Ctx) SWCSMBackupInitNoIC(sessionHandle SessionHandle, passwd []byte) error {
	cPasswd := C.CBytes(passwd)
	defer C.free(cPasswd)

	rv := C.SWCSMBackupInitNoIC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_SM1_ECB, (*C.SGD_UCHAR)(cPasswd), C.SGD_UINT32(len(passwd)))
	return ToError(rv)
}

// SWCSMBackupExportECCKey 18.备份导出ECC密钥对
func (c *Ctx) SWCSMBackupExportECCKey(sessionHandle SessionHandle, keyIndex uint32) (keyData []byte, err error) {
	keyBits := ECCref_MAX_BITS
	keyDataLength := uint32(0)

	keyDataPtr := C.malloc(C.size_t(96) * C.sizeof_uchar) // 官方密钥密文需要96字节空间
	if keyDataPtr == nil {
		return nil, errors.New("failed to allocate memory")
	}
	defer C.free(keyDataPtr)

	rv := C.SWCSMBackupExportECCKey(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex),
		(*C.SGD_UINT32)(unsafe.Pointer(&keyBits)), (*C.SGD_UCHAR)(keyDataPtr), (*C.SGD_UINT32)(unsafe.Pointer(&keyDataLength)))

	keyData = C.GoBytes(unsafe.Pointer(keyDataPtr), C.int(keyDataLength))
	return keyData, ToError(rv)
}

// SWCSMBackupFinal 20.备份结束
func (c *Ctx) SWCSMBackupFinal(sessionHandle SessionHandle) error {
	rv := C.SWCSMBackupFinal(c.libHandle, C.SGD_HANDLE(sessionHandle))
	return ToError(rv)
}

// SWCSMRestoreInitNoIC 21.恢复初始化
func (c *Ctx) SWCSMRestoreInitNoIC(sessionHandle SessionHandle, passwd []byte) error {
	cPasswd := C.CBytes(passwd)
	defer C.free(cPasswd)

	rv := C.SWCSMRestoreInitNoIC(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_SM1_ECB, (*C.SGD_UCHAR)(cPasswd), C.SGD_UINT32(len(passwd)))
	return ToError(rv)
}

// SWCSMRestoreImportECCKey 23.恢复导入ECC密钥对
func (c *Ctx) SWCSMRestoreImportECCKey(sessionHandle SessionHandle, keyIndex uint32, keyData []byte) error {
	cKeyData := C.CBytes(keyData)
	defer C.free(cKeyData)

	maxBits := uint32(ECCref_MAX_BITS)

	rv := C.SWCSMRestoreImportECCKey(c.libHandle, C.SGD_HANDLE(sessionHandle), C.SGD_UINT32(keyIndex), C.SGD_UINT32(maxBits),
		(*C.SGD_UCHAR)(cKeyData), C.SGD_UINT32(len(keyData)))
	return ToError(rv)
}

// SWCSMRestoreFinal 25.恢复结束
func (c *Ctx) SWCSMRestoreFinal(sessionHandle SessionHandle) error {
	rv := C.SWCSMRestoreFinal(c.libHandle, C.SGD_HANDLE(sessionHandle))
	return ToError(rv)
}
