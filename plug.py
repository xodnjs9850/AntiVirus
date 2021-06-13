# _*_ coding:utf-8 _*_

import os
import hashlib

class KavMain:
	#플러그 엔진 초기화
	def init(self, plugins_path):
		return 0
	
	#플러그 엔진 종료
	def uninit(self):
		return 0
	
	#악성코드 검사
	def scan(self, filehandle, filename):
		try:
			mm = filehandle			
			size = os.path.getsize(filename)
			if size == 68:
				m = hashlib.md5()
				m.update(mm[:68])
				fmd5 = m.hexdigest()
				
			if fmd5 == '69630e4574ec6798239b091cda43dca0'
				return True, "EICAR-Test-File (not a virus)", 0
		except IOError:
			pass
			
		return False, '', -1	
	
	#악성코드 치료
	def disinfected(self, filename, malware_id):
		try:
			if malware_id == 0:
				os.remove(filename)
				return True
		
		except IOError:
			pass
			
		return False
	
	#진단 가능한 악성코드 리스트
	def viruslist(self):
		pass
	
	#플러그인 엔진 주요정보
	def getinfo(self):
		pass