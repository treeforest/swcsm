package base

const (
	ECCref_MAX_BITS = 256
	ECCref_MAX_LEN  = 32
)

// KeyType 密钥类型
type KeyType uint32

const (
	KEYTYPE_SYMMETRIC KeyType = 1 // 对称密钥类型
	KEYTYPE_ECC       KeyType = 3 // ECC密钥类型
	KEYTYPE_RSA       KeyType = 4 // RSA密钥类型
)

type ECCrefPublicKey struct {
	Bits uint
	X    []byte
	Y    []byte
}

type ECCrefPrivateKey struct {
	Bits uint
	D    string
}
