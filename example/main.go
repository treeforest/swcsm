package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	log "github.com/treeforest/logger"
	"github.com/treeforest/swcsm"
	"os"
)

var sdfHandle *swcsm.SDFHandle

func exampleInitDevice() {
	log.Info(">> 设备初始化")
	err := sdfHandle.InitDevice()
	if err != nil {
		log.Fatal(err)
	}
}

func exampleGenerateECCKeyPair(keyIndex uint32) {
	log.Infof(">> 产生ECC签名密钥 | 索引:%d", keyIndex)
	err := sdfHandle.GenerateECCSignKeyPair(keyIndex)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof(">> 产生ECC加密密钥 | 索引:%d", keyIndex)
	err = sdfHandle.GenerateECCEncryptKeyPair(keyIndex)
	if err != nil {
		log.Fatal(err)
	}
}

func exampleGetECCKeyStatus() {
	log.Info(">> 查看ECC密钥状态")
	keyStatus, maxKeyCount, err := sdfHandle.GetECCKeyStatus()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("key status: ", keyStatus)
	log.Info("max key count: ", maxKeyCount)
}

func exampleGetRSAKeyStatus() {
	log.Info(">> 查看RSA密钥状态")
	keyStatus, maxKeyCount, err := sdfHandle.GetRSAKeyStatus()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("key status: ", keyStatus)
	log.Info("max key count: ", maxKeyCount)
}

func exampleGetSymmetricKeyStatus() {
	log.Info(">> 查看对称密钥状态")
	keyStatus, maxKeyCount, err := sdfHandle.GetSymmetricKeyStatus()
	if err != nil {
		log.Fatal(err)
	}
	log.Info("key status: ", keyStatus)
	log.Info("max key count: ", maxKeyCount)
}

func exampleImportECCKeyPair(keyIndex uint32) {
	key, _ := sm2.GenerateKey(rand.Reader)
	fmt.Println("D: ", key.D.Bytes())
	fmt.Println("X: ", key.PublicKey.X.Bytes())
	fmt.Println("Y: ", key.PublicKey.Y.Bytes())

	log.Infof(">> 导入ECC签名密钥 | 索引:%d", keyIndex)
	err := sdfHandle.ImportECCSignKeyPair(keyIndex, key)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof(">> 导入ECC加密密钥 | 索引:%d", keyIndex)
	err = sdfHandle.ImportECCEncryptKeyPair(keyIndex, key)
	if err != nil {
		log.Fatal(err)
	}
}

func exampleDestroyECCKeyPair(keyIndex uint32) {
	log.Infof(">> 删除ECC签名密钥 | 索引:%d", keyIndex)
	err := sdfHandle.DestroyECCSignKeyPair(keyIndex)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof(">> 删除ECC加密密钥 | 索引:%d", keyIndex)
	err = sdfHandle.DestroyECCEncryptKeyPair(keyIndex)
	if err != nil {
		log.Fatal(err)
	}
}

func exampleBackupECCKey(passwd []byte, backupPath string) {
	log.Infof(">> 备份导出ECC密钥 | backupPath: %s", backupPath)
	backupData, err := sdfHandle.BackupExportECCKey(passwd)
	if err != nil {
		log.Fatal(err)
	}
	err = os.WriteFile(backupPath, backupData, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func exampleRestoreECCKey(passwd []byte, backupPath string) {
	log.Infof(">> 恢复导入ECC密钥 | backupPath: %s", backupPath)
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		log.Fatal(err)
	}
	err = sdfHandle.RestoreImportECCKey(passwd, backupData)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	libPath := flag.String("lib", "/lib/libswsds.so", "path to library")
	initDevice := flag.Bool("initDevice", false, "init device")
	generateECCKeyPair := flag.Bool("generateECCKeyPair", false, "generate ECC key pair")
	getECCKeyStatus := flag.Bool("getKeyECCStatus", false, "get ECC key status")
	getRsaKeyStatus := flag.Bool("getRsaKeyStatus", false, "get RSA key status")
	getSymmetricKeyStatus := flag.Bool("getSymmetricKeyStatus", false, "get Symmetric key status")
	importECCKeyPair := flag.Bool("importECCKeyPair", false, "import ECC key pair")
	destroyECCKeyPair := flag.Bool("destroyECCKeyPair", false, "destroy ECC key pair")
	backupECCKey := flag.Bool("backupECCKey", false, "backup ECC key pair")
	restoreECCKey := flag.Bool("restoreECCKey", false, "restore ECC key pair")
	keyIndex := flag.Uint("keyIndex", 1, "key index")
	passwd := flag.String("passwd", "12345678", "password")
	backupPath := flag.String("backupPath", "./swcsm.bak", "path to backup")
	flag.Parse()

	var err error
	sdfHandle, err = swcsm.New(*libPath, 10)
	if err != nil {
		log.Fatal(err)
	}
	defer sdfHandle.Close()

	switch {
	case *initDevice:
		exampleInitDevice()
	case *generateECCKeyPair:
		exampleGenerateECCKeyPair(uint32(*keyIndex))
	case *getECCKeyStatus:
		exampleGetECCKeyStatus()
	case *getRsaKeyStatus:
		exampleGetRSAKeyStatus()
	case *getSymmetricKeyStatus:
		exampleGetSymmetricKeyStatus()
	case *importECCKeyPair:
		exampleImportECCKeyPair(uint32(*keyIndex))
	case *destroyECCKeyPair:
		exampleDestroyECCKeyPair(uint32(*keyIndex))
	case *backupECCKey:
		exampleBackupECCKey([]byte(*passwd), *backupPath)
	case *restoreECCKey:
		exampleRestoreECCKey([]byte(*passwd), *backupPath)
	}
}
