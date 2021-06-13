import os
import hashlib
import pefile

#Scan Virus
def ScanVirus(vdb, vsize, sdb, fname) :
	ret, vname = ScanHash(vdb, vsize, fname)
	
	if ret == True :
		return ret, vname

	fp = open(fname, 'rb')                                  # fname 열기
	for t in sdb :
		if ScanStr(fp, t[0], t[1]) == True :
			ret = True
			vname = t[2]
		break
	return ret, vname

#Chack Virus
def SearchVDB(vdb, fmd5):
	for t in vdb:
		if t[0] == fmd5:                                    # imp hash값이 일치할 경우
			return True, t[1]

	return False, ''

#HASH Scan
def ScanHash(vdb, vsize, fname):
	ret = False
	vname = ''

	size = os.path.getsize(fname)                           # fname의 size 불러오기

	if vsize.count(size) :                                  # vsize에 size 값이 있을 경우
		file = pefile.PE(fname)                             # imp hash값을 위해 PE 구조 불러오기
		fmd5 = file.get_imphash()                           # imp hash값 불러오기
		ret, vname = SearchVDB(vdb, fmd5)
		file.close()                                        # file 닫기
	return ret, vname

#Location Search
def ScanStr(fp, offset, mal_str) :
	size = len(mal_str)                                     # mal_str의 길이 size에 저장

	fp.seek(offset)                                         # 리스트 위치 변경
	buf = fp.read(size)                                     # 리스트 탐지 문자열 불러오기
	
	if buf.decode('utf-8') == mal_str :                     # 문자열 탐지
		return True
	else :
		return False

