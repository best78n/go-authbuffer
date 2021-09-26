package gme

import (
    "bytes"
    "encoding/binary"
    "math/rand"
    b64 "encoding/base64"
    "strconv"
    "time"
)

const (
    Tencent_Appid       = 1400000000
    Tencent_Appkey      = "ffffffffffffffff"
    Tencent_AccountType = 26590

    DELTA              = 0x9e3779b9
    SALT_LEN           = 2
    ZERO_LEN           = 7
    ROUNDS             = 16
    LOG_ROUNDS         = 4
    PB_GIANT_VOICE_VER = 16

    MaxLen = 64
)

func write_int16(src *[]byte, s uint16) {
    *src = append(*src, byte((s>>8)&0xff))
    *src = append(*src, byte((s)&0xff))
}
func write_bytes(src *[]byte, in *[]byte) {
    for _, b := range *in {
        *src = append(*src, b)
    }
}
func write_int32(src *[]byte, s uint32) {
    *src = append(*src, byte((s>>24)&0xff))
    *src = append(*src, byte((s>>16)&0xff))
    *src = append(*src, byte((s>>8)&0xff))
    *src = append(*src, byte((s)&0xff))
}
func OI_TeaEncryptECB_1(src *[8]byte, key *string, out *[MaxLen]byte, start uint32) uint32 {
    var y, z uint32
    var sum uint32
    var k [4]uint32
    var i uint32

    y = binary.BigEndian.Uint32((*src)[0:4])
    z = binary.BigEndian.Uint32((*src)[4:8])

    keyBuf := []byte(*key)
    for i = 0; i < 4; i++ {
        k[i] = binary.BigEndian.Uint32(keyBuf[i*4 : i*4+4])
    }
    sum = 0
    for i = 0; i < ROUNDS; i++ {
        sum += DELTA
        y += ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1])
        z += ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3])
    }
    temBuf := new(bytes.Buffer)
    err := binary.Write(temBuf, binary.BigEndian, y) //binary.BigEndian
    if err != nil {
        return 1
    }
    err = binary.Write(temBuf, binary.BigEndian, z) //BigEndian
    if err != nil {
        return 1
    }
    for i = 0; i < 8; i++ {
        (*out)[start+i] = temBuf.Bytes()[i]
    }

    return 0
}
func symmetry_encrypt(src *[]byte, key string, out *[MaxLen]byte) int {
    var length = 0
    var nPadlen uint8
    var src_buf [8]byte
    var zero_iv = [8]byte{0}
    var src_i, i, j int32
    nInBufLen := len(*src)
    nPadlen = (uint8(len(*src)) + 1 + SALT_LEN + ZERO_LEN) % 8
    if nPadlen != 0 {
        nPadlen = 8 - nPadlen
    }
    src_buf[0] = byte(uint8(rand.Intn(0xff)&0x0f8) | nPadlen)
    src_i = 1
    for {
        if nPadlen <= 0 {
            break
        }
        src_buf[src_i] = byte(rand.Intn(0xff))
        src_i++
        nPadlen--
    }
    offIndex := uint32(0)
    iv_buf := zero_iv[:]
    for i = 1; i <= SALT_LEN; {
        if src_i < 8 {
            src_buf[src_i] = byte(rand.Intn(0xff))
            src_i++
            i++
        }
        if src_i == 8 {
            for j = 0; j < 8; j++ {
                src_buf[j] ^= iv_buf[j] //(*out)[j + int32(readIndx)]
            }
            err := OI_TeaEncryptECB_1(&src_buf, &key, out, offIndex)
            if err != 0 {
                return 0
            }
            src_i = 0
            iv_buf = (*out)[offIndex : offIndex+8]
            offIndex += 8
            length += 8
        }
    }
    newReadIndx := 0
    for {
        if nInBufLen <= 0 {
            break
        }
        if src_i < 8 {
            src_buf[src_i] = (*src)[newReadIndx]
            newReadIndx++
            src_i++
            nInBufLen--
        }
        if src_i == 8 {
            for i = 0; i < 8; i++ {
                src_buf[i] ^= iv_buf[i]
            }
            err := OI_TeaEncryptECB_1(&src_buf, &key, out, offIndex)
            if err != 0 {
                return 0
            }
            src_i = 0
            iv_buf = (*out)[offIndex : offIndex+8]
            offIndex += 8
            length += 8
        }
    }

    for i = 1; i <= ZERO_LEN; {
        if src_i < 8 {
            src_buf[src_i] = 0
            src_i++
            i++
        }
        if src_i == 8 {
            for j = 0; j < 8; j++ {
                src_buf[j] ^= iv_buf[j]
            }
            err := OI_TeaEncryptECB_1(&src_buf, &key, out, offIndex)
            if err != 0 {
                return 0
            }
            iv_buf = (*out)[offIndex : offIndex+8]
            src_i = 0
            offIndex += 8
            length += 8
        }
    }
    return length
}
func authbuffer(appId uint32, authId uint32, account string, accountType uint32, key string, expTime uint32, privilegeMap uint32) []byte {
    var retAuthBuff []byte
    cVer := byte(0)
    var wAccountLen uint16 = uint16(len(account))
    retAuthBuffByte := []byte(account)
    retAuthBuff = append(retAuthBuff, cVer)

    write_int16(&retAuthBuff, wAccountLen)
    write_bytes(&retAuthBuff, &retAuthBuffByte)
    write_int32(&retAuthBuff, appId)
    write_int32(&retAuthBuff, authId)
    write_int32(&retAuthBuff, expTime)
    write_int32(&retAuthBuff, privilegeMap)
    write_int32(&retAuthBuff, accountType)
    var outAuthBuff = [MaxLen]byte{0}
    count := symmetry_encrypt(&retAuthBuff, key, &outAuthBuff)
    //fmt.Print(fmt.Sprintf("iv_buf:%+v:%s:%d:%d\n", retAuthBuff,account,wAccountLen,len(retAuthBuff)))
    if count == 0 {
        return nil
    }
    return outAuthBuff[:count]
}

//roomId and appId must be greater than 10000
func Authbuffer(roomId uint32, appId uint32) string {
    sOpenID := strconv.FormatUint(uint64(appId),10)
    expireTime := time.Now().Unix() + 1800

    key := authbuffer(Tencent_Appid, roomId, sOpenID, Tencent_AccountType, Tencent_Appkey, uint32(expireTime), 0xffff)
    if key == nil {
        return ""
    }
    sEnc := b64.StdEncoding.EncodeToString(key)
    return sEnc
}

