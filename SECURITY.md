# Security Model

This document outlines the security provided by this tool. In short: 

- a leaked password breaks confidentiality and integrity of the corresponding file and no other files
- read access to the SecretManager breaks confidentiality and integrity of all files for which the password can be read
- write access to the SecretManager breaks integrity of all files, but not confidentiality

## Attacker Model

We will assume the attacker has full access to the wrapped files where they are stored.
The attacker can read these files and can modify these files without your knowledge. 

We will consider the security provided given different assumptions about an attacker's
level of access to the SecretManager and in the face of different leaks. 

## No Access to SecretManager 

This is the "standard" attacker model for this tool. The SecretManager (i.e. 1Password) is the root of trust for all secret material. Below, we discuss what it would mean if an attacker
get specific levels of access to your SecretManager.

### A given password is leaked

At the moment _all_ *Integrity* is lost and *Confidentiality* is lost for the file for which
the password was leaked.

*Integrity* is lost for all files with the following attack:
    - an attacker knows a password to file A.
        - we also assume the attacker knows how to find the location of the password
          in the secret manager (i.e. the 1Password ID) as this is not secret.
    - The attacker modifies file B, changing the password identifier to point to the known password. Then, the attacker arbitrarily modifies the data of the file.
    - The attacker then computes a new HMAC with a new key derived from the salt in the file (or a new one if desired for some reason) and the password and replaces the old HMAC.
    - The verifier will lookup the known password (not able to detect that it is no longer the original password), and verify the new HMAC which will succeed. 

#### Fix

We can include the hash of the file in the secrets manager. Then, a given secret is linked
to a given file. This would still potentially allow an attacker to replace a file with the 
compromised file, leading to a specific sort of integrity violation. We can remediate this by including the filename in the authenticated part of the message and checking if the current filename matches the filename at wrap time. 

Then, if A is compromised and you download B and it has the contents of A, you will be warned of a name mismatch. Because users may want to change names themselves and because the scope of this attack is quite limited, this will be a warning, not a failure. 

## Read Access to SecretManager

In the event of full read access, all guarantees are lost as all keys are now known to the attacker. 

### Read Access to a given password

This is the same as the [above section](#A-given-password-is-leaked).

## Write Access to SecretManager

(_Note: This section considers write acces without read access_ )

In the event of _any_ write access, *Confidentiality* remains intact on existing wrapped files (although _unwrapping_ and _rewrapping_ a file will break *Confidentiality* as the attacker could swap the original key for a new key without your knowledge between the unwrap and the wrap step).

*Integrity* is lost, as the attacker can write new secrets into your secret manager,
modify a file to point to that new secret, and then change the contents of the file arbitrarily.

