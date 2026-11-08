from app.core import *
def test_modexp():assert modexp(5,12345)==pow(5,12345,P)
def test_dh():
 a,ap=dh_keypair();b,bp=dh_keypair();assert dh_shared(a,bp)==dh_shared(b,ap)
def test_crypto():
 c=crypt('hello',12345,'abc');assert decrypt(c,12345,'abc')=='hello'
def test_tag():
 c=crypt('hello',12345,'abc');assert tag(c,12345,'abc')!=tag(c[:-2]+'00',12345,'abc')
