# Line__Crypt
A small tool to decrypt F-Zero GX's line__.bin to an .lz archive and vice versa.

## Usage
### Decryption
Paste the line__.bin file into the folder containing Line__Crypt.exe. Double-click the decrypt_JPN.bat if your file corresponds to the Japanese release of F-Zero GX. Double-click the decrypt_INT.bin if your file corresponces to the European or American release.

### Encryption
Paste the line__.rel.lz file into the folder containing Line__Crypt.exe. Double-click the encrypt_JPN.bat if your file corresponds to the Japanese release of F-Zero GX. Double-click the encrypt_INT.bin if your file corresponds  to the European or American release.

### Usage Advice
Rename already existing .bin and .rel.lz files if you don't want them to be overwritten

If you want to use command line instead, use the following command structure:
`Line__Crypt.exe inputFile regionFlag`
Region Flags: INT for the American and European releases, JPN for the Japanese release 

Example:
`"C:/tools/Line__Crypt/Line__Crypt.exe" "C:/game/GFZP01/line__.bin" INT`
