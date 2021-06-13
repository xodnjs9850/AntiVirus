import sys                                                  # sys 모듈 불러오기
import os                                                   # os 모듈 불러오기
import hashlib                                              # hashlib 모듈 불러오기
import io                                                   # io 모듈 불러오기
import base64                                               # base64 모듈 불러오기
import scanmod                                              # scanmod.py 불러오기
import curemod                                              # curemod.py 불러오기
from Crypto import Random                                   # Random 모듈 불러오기
from Crypto.Cipher import AES                               # AES 모듈 불러오기

BS=16                                                       # BS 선언
unpad = lambda s: s[:-ord(s[len(s)-1:])]                    # unpad 식
key = "gozldgkwlak1!"                                       # salt 값
VirusDB = []
vdb = []
vsize = []
sdb = []

#Decoding KMD
class AESCipher:
    def __init__( self, key ):
        self.key = key
        self.key = hashlib.sha256(key.encode()).digest()    # key 값을 sha256으로 암호화
    
    def decrypt(self, enc):
        enc = enc[4:]                                       # enc 값의 첫번째 자리부터 4번째 자리까지 자르기
        enc = base64.b64decode(enc)                         # enc 값 base64로 decode
        iv = enc[:16]                                       # enc 값 맨 뒤에서부터 16자리 자르기
        cipher = AES.new(self.key, AES.MODE_CBC, iv)        # AES 함수에 key 값과 암호화 값 넣기
        back = unpad(cipher.decrypt( enc[16:] )).decode()   # 암호화 값 decrypt하여 unpad 진행
        return back

def DecodeKMD(fname) :
    try :

        fp = open(fname,'rb')                               # fname 파일 open
        buf = fp.read()                                     # fname 파일 읽어오기
        fp.close()                                          # 파일 닫기

        cip = AESCipher(key)                                # AESCipher 선언 및 AESCipher key 값 초기화
        buf2 = cip.decrypt(buf)                             # fname 파일에서 읽어온 암호화 값 decrypt 함수에 넣기
        return buf2

    except:
        pass                                                # error 발생시 pass

    return None

#Loading VirusDB 
def LoadVirusDB() :
    buf = DecodeKMD('virus.kmd')                            # DecodeKMD 함수에 virus.kmd 파일 넣기
    fp = io.StringIO(buf)                                   # 복호화한 내용 읽어 fp에 저장

    while True :
        line = fp.readline()                                # 한 줄씩 읽어오기
        if not line : break                                 # 더이상 읽어올 내용이 없을 시 break

        line = line.strip()                                 # 한 줄씩 자르기
        VirusDB.append(line)                                # 한 줄씩 VirusDB에 삽입
    fp.close()                                              # 파일 닫기

def MakeVirusDB() :
    for i in VirusDB :
        t = []
        v = i.split(':')                                    # VirusDB를 : 기준으로 자르기

        scan_func = v[0]                                    # v 리스트에서 1번째 원소값 가져오기
        cure_func = v[1]                                    # v 리스트에서 2번째 원소값 가져오기

        if scan_func == 'ScanHash' :
            t.append(v[3])                                  # v 리스트에서 3번째 원소값 t 리스트에 추가
            t.append(v[4])                                  # v 리스트에서 4번째 원소값 t 리스트에 추가
            vdb.append(t)                                   # vdb 리스트에 t 리스트 추가
            size = int(v[2])                                # v 리스의 2번째 원소값 int로 변환 후 size 변수에 저장

            if vsize.count(size) == 0 :                     # vsize 리스트의 원소값에 size값이 없을때 
                vsize.append(size)                          # vsize 리스트에 size 추가

        elif scan_func == 'ScanStr' :
            t.append(int(v[2]))                             # t 리스트에 v 리스트 2번째 원소값 int형으로 추가
            t.append(v[3])                                  # t 리스트에 v 리스트 3번째 원소값 추가
            t.append(v[4])                                  # t 리스트에 v 리스트 4번째 원소값 추가
            sdb.append(t)                                   # sdb에 t 리스트 추가

if __name__ == '__main__' :
    LoadVirusDB()
    MakeVirusDB()
           
    print('\n')
    print('██╗   ██╗    ██████╗      ██████╗ ') 
    print('██║   ██║    ██╔══██╗     ██╔══██╗')
    print('██║   ██║    ██║  ██║     ██████╔╝')
    print('╚██╗ ██╔╝    ██║  ██║     ██╔═══╝ ')
    print(' ╚████╔╝ ██╗ ██████╔╝ ██╗ ██║     ')
    print('  ╚═══╝  ╚═╝ ╚═════╝  ╚═╝ ╚═╝     ')
    
    print("mod를 선택하세요.\n")
    print("1. virus remove mod")
    print("2. virus detection mod")
    print("another input is system exit.")
    print("\n")
    i = input("select mod : ")
    
    if i == '1' :
        fname = input("input the virus. : ")
        ret, vname = scanmod.ScanVirus(vdb, vsize, sdb, fname)  # scanmod의 ScanVirus 함수를 실행
        curemod.CureDelete(fname)
        print("remove the virus!!\n")
        print(('%s : %s') % (fname, vname))
        if ret == False :
            print(('%s : ok') % (fname))
            print("This file is not virus!\n")
    
    elif i == '2' :
        fname = input("input the virus. : ")
        ret, vname = scanmod.ScanVirus(vdb, vsize, sdb, fname)
        print("detection the virus!\n")
        print(('%s : %s') % (fname, vname))
        if ret == False :
            print(('%s : ok') % (fname))
            print("This file is not virus!\n")
    
    else :
        print("system exit.")
    
    #fname = sys.argv[1]                                     # 인자값을 fname에 저장
    
    #if ret == True :
        #print(('%s : %s') % (fname, vname))
        #curemod.CureDelete(fname)
    #else :
        #print(('%s : ok') % (fname))
