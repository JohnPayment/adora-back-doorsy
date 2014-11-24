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
-- RETURNS: The Encrypted string
-- 
-- NOTES: Encrypts (or decrypts) a string using a XOR cypher and a series of pre-defined key phrases.
-- 
---------------------------------------------------------------------------------------------
'''
def encrypt(message):
	newMessage = message
	for key in keys:
		i = 0
		tempMessage = newMessage
		newMessage = ""
		for char in tempMessage:
			newMessage = newMessage + (chr(ord(char) ^ ord(key[i])))
			i = i + 1
			if len(key) <= i:
				i = 0
	return newMessage

