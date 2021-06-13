import sys
import base64
import hashlib
import os
from Crypto import Random
from Crypto.Cipher import AES

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()         # pad 식
key = "gozldgkwlak1!"                                                           # salt 값

class AESCipher:
	def __init__( self, key ):
		self.key = key
		self.key = hashlib.sha256(key.encode()).digest()                        # salt 값 암호화
			
	def encrypt( self, raw ):
		raw = pad(raw)                                                          # 암호값에 pad 추가
		iv = Random.new().read( AES.block_size )                                # iv 값 생성
		cipher = AES.new( self.key, AES.MODE_CBC, iv )                          # AES 암호화
		return base64.b64encode( iv + cipher.encrypt( raw ) ).decode()          # raw 값과 iv를 합친 값을 base64로 암호화

def main() : 
	if len(sys.argv) != 2 :
		print ('Usage : keymake.py [file]')
		return

	fname = sys.argv[1]
	tname = fname

	fp = open(tname, 'rb')
	buf = fp.read()
	fp.close()
		
	cip = AESCipher(key)                                                        # AESCipher 함수 호출 및 key 값 암호화
	buf2 = cip.encrypt(buf)                                                     # buf 값을 encrypt 함수로 암호화

	buf2 = buf2
		
	buf4 = 'KAVM' + buf2                                                        # 암호화값에 KAVM 붙이기
	
	kmd_name = fname.split('.')[0] + '.kmd'                                     # 파일 이름에 .kmd 추가로 붙이기
	fp = open(kmd_name, 'wb')                                                   # 파일 열기
	fp.write(buf4.encode('utf-8'))                                              # 파일에 암호화 내용 쓰기
	fp.close()                                                                  # 파일 닫기
	
	print((('%s -> %s') % (fname, kmd_name)))

if __name__ == '__main__' :
	main()
