package swcsm

import (
	"github.com/pingcap/errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/treeforest/swcsm/base"
)

// InitDevice 初始化设备
func (h *SDFHandle) InitDevice() error {
	return h.withSession(func(session base.SessionHandle) error {
		return h.ctx.SWCSMInitDevice(session)
	})
}

// GenerateECCSignKeyPair 生成ECC签名密钥。keyIndex 为密钥对索引位置，从1开始。
func (h *SDFHandle) GenerateECCSignKeyPair(keyIndex uint32) error {
	return h.withSession(func(session base.SessionHandle) error {
		return h.ctx.SWCSMGenerateECCKeyPair(session, getECCSignKeyIndex(keyIndex))
	})
}

// GenerateECCEncryptKeyPair 生成ECC加密密钥。keyIndex 为密钥对索引位置，从1开始。
func (h *SDFHandle) GenerateECCEncryptKeyPair(keyIndex uint32) error {
	return h.withSession(func(session base.SessionHandle) error {
		return h.ctx.SWCSMGenerateECCKeyPair(session, getECCEncryptKeyIndex(keyIndex))
	})
}

// GetECCKeyStatus 获取ECC密钥状态
func (h *SDFHandle) GetECCKeyStatus() (keyStatus []uint32, maxKeyCount uint32, err error) {
	return h.getKeyStatus(base.KEYTYPE_ECC)
}

// GetRSAKeyStatus 获取RSA密钥状态
func (h *SDFHandle) GetRSAKeyStatus() (keyStatus []uint32, maxKeyCount uint32, err error) {
	return h.getKeyStatus(base.KEYTYPE_RSA)
}

// GetSymmetricKeyStatus 获取对称密钥状态
func (h *SDFHandle) GetSymmetricKeyStatus() (keyStatus []uint32, maxKeyCount uint32, err error) {
	return h.getKeyStatus(base.KEYTYPE_SYMMETRIC)
}

func (h *SDFHandle) getKeyStatus(keyType base.KeyType) (keyStatus []uint32, maxKeyCount uint32, err error) {
	err = h.withSession(func(session base.SessionHandle) error {
		keyStatus, maxKeyCount, err = h.ctx.SDFGetKeyStatus(session, keyType)
		return err
	})
	return
}

// ImportECCSignKeyPair 导入ECC签名密钥
func (h *SDFHandle) ImportECCSignKeyPair(keyIndex uint32, privateKey *sm2.PrivateKey) error {
	return h.withSession(func(session base.SessionHandle) error {
		return h.ctx.SWCSMImportECCKeyPair(session, getECCSignKeyIndex(keyIndex), privateKey)
	})
}

// ImportECCEncryptKeyPair 导入ECC加密密钥
func (h *SDFHandle) ImportECCEncryptKeyPair(keyIndex uint32, privateKey *sm2.PrivateKey) error {
	return h.withSession(func(session base.SessionHandle) error {
		return h.ctx.SWCSMImportECCKeyPair(session, getECCEncryptKeyIndex(keyIndex), privateKey)
	})
}

// DestroyECCSignKeyPair 销毁ECC签名密钥
func (h *SDFHandle) DestroyECCSignKeyPair(keyIndex uint32) error {
	return h.withSession(func(session base.SessionHandle) error {
		return h.ctx.SWCSMDestroyECCKeyPair(session, getECCSignKeyIndex(keyIndex))
	})
}

// DestroyECCEncryptKeyPair 销毁ECC加密密钥
func (h *SDFHandle) DestroyECCEncryptKeyPair(keyIndex uint32) error {
	return h.withSession(func(session base.SessionHandle) error {
		return h.ctx.SWCSMDestroyECCKeyPair(session, getECCEncryptKeyIndex(keyIndex))
	})
}

type BackupECCKeyItem struct {
	Index   uint32 `json:"index,omitempty"`
	KeyData []byte `json:"key_data,omitempty"`
}

// BackupExportECCKey 备份导出所有ECC密钥
func (h *SDFHandle) BackupExportECCKey(passwd []byte) ([]byte, error) {
	err := checkPassword(passwd)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var backupData []byte
	err = h.withSession(func(session base.SessionHandle) error {
		err := h.ctx.SWCSMBackupInitNoIC(session, passwd)
		if err != nil {
			return errors.WithStack(err)
		}

		keyStatus, _, err := h.ctx.SDFGetKeyStatus(session, base.KEYTYPE_ECC)
		if err != nil {
			return errors.WithStack(err)
		}

		items := make([]BackupECCKeyItem, 0)
		for i, status := range keyStatus {
			if status == 0 {
				continue
			}
			keyIndex := uint32(i + 1)
			keyData, err := h.ctx.SWCSMBackupExportECCKey(session, keyIndex)
			if err != nil {
				return errors.WithStack(err)
			}
			items = append(items, BackupECCKeyItem{
				Index:   keyIndex,
				KeyData: keyData,
			})
		}

		err = h.ctx.SWCSMBackupFinal(session)
		if err != nil {
			return errors.WithStack(err)
		}

		backupData, err = GobEncode(items)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})

	return backupData, err
}

// RestoreImportECCKey 备份导入所有ECC密钥
func (h *SDFHandle) RestoreImportECCKey(passwd []byte, backupECCKeyData []byte) error {
	err := checkPassword(passwd)
	if err != nil {
		return errors.WithStack(err)
	}

	var items []BackupECCKeyItem
	err = GobDecode(backupECCKeyData, &items)
	if err != nil {
		return errors.WithStack(err)
	}

	return h.withSession(func(session base.SessionHandle) error {
		err = h.ctx.SWCSMRestoreInitNoIC(session, passwd)
		if err != nil {
			return errors.WithStack(err)
		}

		for _, item := range items {
			err = h.ctx.SWCSMRestoreImportECCKey(session, item.Index, item.KeyData)
			if err != nil {
				return errors.WithStack(err)
			}
		}

		err = h.ctx.SWCSMRestoreFinal(session)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})
}

func getECCSignKeyIndex(keyIndex uint32) uint32 {
	return 2*keyIndex - 1
}

func getECCEncryptKeyIndex(keyIndex uint32) uint32 {
	return 2 * keyIndex
}

func checkPassword(password []byte) error {
	n := len(password)
	if n < 8 || n > 16 {
		return errors.New("password length must be between 8 and 16")
	}
	return nil
}
