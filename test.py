# Reads test vectors from HMAC_DRBG.rsp, and tests them against the HMAC_DRBG
# module.
# HMAC_DRBG.rsp is from drbgvectors_pr_false.zip, which can be found in the DRBG
# Test Vectors archive from http://csrc.nist.gov/groups/STM/cavp/.
import sys
from hmac_drbg import HMAC_DRBG


# A hacked together way to parse the rsp test vector files.
def read_entry (f, expected_name):
	name,value = f.readline ().strip ().split ('=')
	name = name.strip ()
	value = value.strip ()

	assert name == expected_name

	return value

algorithm = ""
tests_performed = 0
with open ('HMAC_DRBG.rsp', 'rb') as f:
	while True:
		line = f.readline ()
		if line == '':
			break

		line = line.strip ()

		if line.startswith ('[') and not '=' in line:
			algorithm = line

		if algorithm != '[SHA-256]':
			continue

		if not line.startswith ('COUNT'):
			continue

		# Read stimulus and expected result
		EntropyInput = read_entry (f, 'EntropyInput').decode ('hex')
		Nonce = read_entry (f, 'Nonce').decode ('hex')
		PersonalizationString = read_entry (f, 'PersonalizationString').decode ('hex')
		EntropyInputReseed = read_entry (f, 'EntropyInputReseed').decode ('hex')
		AdditionalInputReseed = read_entry (f, 'AdditionalInputReseed').decode ('hex')
		AdditionalInput0 = read_entry (f, 'AdditionalInput').decode ('hex')
		AdditionalInput1 = read_entry (f, 'AdditionalInput').decode ('hex')
		ReturnedBits = read_entry (f, 'ReturnedBits').decode ('hex')

		# This implementation does not support additional input
		if AdditionalInputReseed != '' or AdditionalInput0 != '' or AdditionalInput1 != '':
			continue

		# Test
		drbg = HMAC_DRBG (entropy=(EntropyInput + Nonce), personalization_string=PersonalizationString)
		drbg.reseed (entropy=EntropyInputReseed)
		drbg.generate (len (ReturnedBits))
		result = drbg.generate (len (ReturnedBits))

		if result != ReturnedBits:
			print "FAILURE"
			print "EntropyInput = ", EntropyInput.encode ('hex')
			print "Nonce = ", Nonce.encode ('hex')
			print "PersonalizationString = ", PersonalizationString.encode ('hex')
			print "EntropyInputReseed = ", EntropyInputReseed.encode ('hex')
			print "AdditionalInputReseed = ", AdditionalInputReseed.encode ('hex')
			print "AdditionalInput = ", AdditionalInput0.encode ('hex')
			print "AdditionalInput = ", AdditionalInput1.encode ('hex')
			print "ReturnedBits = ", ReturnedBits.encode ('hex')
			sys.exit (-1)

		tests_performed += 1


print "PASSED! Performed %d tests." % tests_performed
