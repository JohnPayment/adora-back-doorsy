keys = ["This is the first key", "ABCDEFGHIJKLMNOP", "Keys are applied sequentially such that patterns cause by them being shorter than the payload become obscured."]

'''
---------------------------------------------------------------------------------------------
-- 
-- FUNCTION: encrypt
-- 
-- DATE: 2014-11-14
-- 
-- DESIGNERS: John Payment
-- 
-- PROGRAMMER: John Payment
-- 
-- INTERFACE: encrypt(message)
--              message - The message to be encrypted or decryped
-- 
-- RETURNS: N/A
-- 
-- NOTES: 
-- 
---------------------------------------------------------------------------------------------
'''
def encrypt(message):
	newMessage = ""
	for key in keys:
		i = 0
		for char in message:
			newMessage = newMessage + (chr(ord(char) ^ ord(key[i])))
			i = i + 1
			if len(key) <= i:
				i = 0
	return newMessage

