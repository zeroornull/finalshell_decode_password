package main

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"regexp"
)

// 结构体用于存储解密请求的数据
type DecryptRequest struct {
	EncodedData string `json:"encoded_data"`
}

// 删除不可见字符
func removeNonPrintableChars(input string) string {
	re := regexp.MustCompile(`[\x00-\x1F\x7F-\x9F]`)
	return re.ReplaceAllString(input, "")
}

// 伪随机数生成器
type Random struct {
	seed int64
}

func NewRandom(seed int64) *Random {
	return &Random{seed: (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)}
}

func (r *Random) next(bits int) int64 {
	r.seed = (r.seed*0x5DEECE66D + 0xB) & ((1 << 48) - 1)
	value := r.seed >> (48 - bits)
	if value < (1 << (bits - 1)) {
		return value
	}
	return value - (1 << bits)
}

func (r *Random) nextLong() int64 {
	return (r.next(32) << 32) + r.next(32)
}

// DES解密
func desDecode(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data)%8 != 0 {
		return nil, fmt.Errorf("data length is not a multiple of 8")
	}

	dst := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block.Decrypt(dst[i:i+8], data[i:i+8])
	}
	return dst, nil
}

// 随机密钥生成
func randomKey(head []byte) []byte {
	ilist := []int{24, 54, 89, 120, 19, 49, 85, 115, 14, 44, 80, 110, 9, 40, 75, 106, 43, 73, 109, 12, 38, 68, 104, 7, 33, 64,
		99, 3, 28, 59, 94, 125, 112, 16, 51, 82, 107, 11, 46, 77, 103, 6, 41, 72, 98, 1, 37, 67, 4, 35, 70, 101, 0,
		30, 65, 96, 122, 25, 61, 91, 117, 20, 56, 86, 74, 104, 13, 43, 69, 99, 8, 38, 64, 95, 3, 34, 59, 90, 125,
		29, 93, 123, 32, 62, 88, 119, 27, 58, 83, 114, 22, 53, 79, 109, 17, 48, 35, 66, 101, 5, 31, 61, 96, 0, 26,
		56, 92, 122, 21, 51, 87, 117, 55, 85, 120, 24, 50, 80, 116, 19, 45, 75, 111, 14, 40, 71, 106, 10, 50, 81,
		116, 20, 45, 76, 111, 15, 41, 71, 106, 10, 36, 66, 102, 5, 69, 100, 8, 39, 65, 95, 3, 34, 60, 90, 126, 29,
		55, 85, 121, 24, 12, 42, 78, 108, 7, 37, 73, 103, 2, 33, 68, 99, 124, 28, 63, 94, 31, 61, 97, 0, 26, 57,
		92, 123, 21, 52, 87, 118, 17, 47, 82, 113, 100, 4, 39, 70, 96, 126, 34, 65, 91, 121, 30, 60, 86, 116, 25,
		55, 120, 23, 58, 89, 115, 18, 54, 84, 110, 13, 49, 79, 105, 9, 44, 75, 62, 92, 1, 31, 57, 88, 123, 27, 52,
		83, 118, 22, 48, 78, 113, 17, 81, 112, 20, 51, 76, 107, 15, 46, 72, 102, 10, 41, 67, 97, 6, 36}
	i := ilist[head[5]]
	ks := 3680984568597093857 / int64(i)
	rand1 := NewRandom(ks)
	t := head[0]

	for j := 0; j < int(t); j++ {
		rand1.nextLong()
	}

	n := rand1.nextLong()
	rand2 := NewRandom(n)

	ld := []int64{
		int64(head[4]), rand2.nextLong(), int64(head[7]), int64(head[3]), rand2.nextLong(), int64(head[1]), rand1.nextLong(), int64(head[2]),
	}

	byteStream := new(bytes.Buffer)
	for _, l := range ld {
		err := binary.Write(byteStream, binary.BigEndian, l)
		if err != nil {
			return nil
		}
	}

	keyData := md5Hash(byteStream.Bytes())[:8]
	return keyData
}

// MD5哈希
func md5Hash(data []byte) []byte {
	hash := md5.Sum(data)
	return hash[:]
}

// 解密密码
func decodePass(data string) (string, error) {
	if data == "" {
		return "", fmt.Errorf("empty data")
	}

	buf, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	head := buf[:8]
	d := buf[8:]

	key := randomKey(head)

	bt, err := desDecode(d, key)
	if err != nil {
		return "", err
	}

	return removeNonPrintableChars(string(bt)), nil
}

// 处理解密请求
func handleDecrypt(c *gin.Context) {
	var req DecryptRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
		return
	}

	decodedPassword, err := decodePass(req.EncodedData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"decoded_password": decodedPassword})
}

func main() {
	r := gin.Default()

	r.POST("/decode", handleDecrypt)

	err := r.Run(":8080")
	if err != nil {
		return
	} // 启动服务，监听8080端口
}
