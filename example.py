import os
from hmac_drbg import HMAC_DRBG


drbg = HMAC_DRBG (entropy=os.urandom (64))

while True:
	secret = drbg.generate (1)

	if secret is None:
		drbg.reseed (entropy=os.urandom (32))
		secret = drbg.generate (1)

	secret = ord (secret) & 0xF

	print "Guess my lucky number (0 to 15):"
	guess = raw_input ('# ')

	if int (guess) == secret:
		print "You got it!"
	else:
		print "Nope, it was", secret
