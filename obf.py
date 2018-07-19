
from Crypto.Cipher import AES
𐳡=len
𗙦=print
𞸬=AES.MODE_CBC
ﻧ=AES.new
𐮂='0123456789abcdef0123456789abcdef' 
𬕵='This is an IV456' 
𞡅=ﻧ(𐮂,𞸬,𬕵)
쑘='0123456789abcdef'
ﻓ=(16-𐳡(쑘)%16)
쑘+=('ㄻ'*ﻓ)
𗡭=𞡅.encrypt(쑘)
 𗙦(𗡭)
𬁍=ﻧ(𐮂,𞸬,𬕵)
𞢀=𬁍.decrypt(𗡭).decode('utf-8')
𞢀=𞢀[:𞢀.find('ㄻ')]
 𗙦(𞢀)
from Crypto.PublicKey import RSA
𞺭=RSA.generate
𐮂=𞺭(2048)
𡳋=696969
# Created by pyminifier (https://github.com/liftoff/pyminifier)

