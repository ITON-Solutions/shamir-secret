# Shamir secret sharing

A utility for generating Shamir's shared secrets (SSS) in accordance to the SLIP-0039 specification [see here https://github.com/satoshilabs/slips/blob/master/slip-0039.md].

The SSS utility can be used on Android devices as well as desktop applications. To get an idea on the functionality, we recommend you to take a look at the test cases.

The preservation of digital assets is a primary task of any information system and especially of a distributed one. Backup is traditionally used as a preservation method. However, an excessive use of backups by itself can lead to protection risks in the case of sensitive assets, like personal data or Bitcoin wallets.

The Shamir´s secret sharing algorithm provides an implementation for key (secret) recovering. Thus, the content protected by this key (secret) can be also recovered in more reliable way, in particular through the mechanism known as Social Recovery.  This mechanism is based on distributing encrypted parts of a key (secret) among a number of trusted persons (safe-keepers). None of them can recover the key individually. Nevertheless, thanks to SSS the recovery can be achieved inside a limited group of trusted safe-keepers (quorum) that act in cooperation.

The utility has been developed as an integral component of the Ubicua project portfolio [http://www.ubicua.com/].
